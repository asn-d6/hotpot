#!/usr/bin/python

import socket
import ssl
import sys
import argparse
import random
import struct
import logging
import os.path

MAX_OUTGOING_DATA = 300

"""
Represents a connected client.

Some important members of the class are:

- 'Client.data', a dictionary of the form:
  {'pre_ssl': [], 'post_ssl_inc': [], 'post_ssl_out': []}

  Each dictionary key holds a list of data exchanged between the
  server and the client.

  Specifically, 'pre_ssl' contains data sent by the client before the
  SSL handshake, 'post_ssl_inc' contains data sent by the client after
  the SSL handshake and 'post_ssl_out' contains data sent by us (the
  server) after the SSL handshake.

- 'Client.state', represents the current state of the client. It takes
  three values:
  'ST_JUST_CONNECTED': The client just connected.
  'ST_HANDSHAKED': The client finished the SSL handshake and is now
                   sending us application-layer data.
  'ST_HANDLED': The client spoke with us inside the SSL link and the
                conversation is now over.
"""
class Client:
    """
    Given the '_socket' that is used to talk to a client, and a
    client's 'address' and 'port', handle that client.

    'server' is our Server object.
    """
    def __init__(self, server, _socket, address, port):
        self.server = server
        self.socket = _socket
        self.address = address
        self.port = port

        # The SSL socket: non-existent for now since the client just
        # connected.
        self.ssl_socket = None

        # Initiate logging storage for this client.
        self.data = {}
        self.data['pre_ssl'] = []
        self.data['post_ssl_inc'] = []
        self.data['post_ssl_out'] = []

        # Initiate state.
        self.state = "ST_JUST_CONNECTED"

        # Welcome the client: see if he wants to speak SSL and do the
        # SSL handshake.
        retval = self._handle_client_new()

        if (not retval):
            # He didn't want to speak SSL. Log him and kick him.
            self._log_client_and_close_conn()
            return

        self.state = "ST_HANDSHAKED"
        assert(self.ssl_socket)

        retval = self._handle_client_ssl()

        self.state = "ST_HANDLED"

        self._log_client_and_close_conn()

    """We have a new client, see if he wants to speak SSL and if so,
    try to do the SSL handshake with him. Return True if the handshake
    was done successfully, otherwise return False."""
    def _handle_client_new(self):
        # Peek into the data he sent us. We won't be able to see the
        # traffic after the socket is SSL-wrapped.
        self.data['pre_ssl'].append(self.socket.recv(4096, socket.MSG_PEEK))

        try:
            self.ssl_socket = ssl.wrap_socket(self.socket,
                                              server_side=True,
                                              certfile=self.server.get_ssl_files(),
                                              keyfile=self.server.get_ssl_files(),
                                              ssl_version=ssl.PROTOCOL_TLSv1)
        except ssl.SSLError: # if we get an ssl.SSLError it means that
                             # the client screwed up the SSL handshake.
            return False

        return True

    """We have a client who finished the SSL handshake and is now
    sending us application-layer data. Handle him."""
    def _handle_client_ssl(self):
        data = self.ssl_socket.recv(4096)

        # Log any data the client sends us, and send the client some
        # dummy data of our own as well.
        while data:
            self.data['post_ssl_inc'].append(data)
            if (not self.server.is_laconic()):
                self._send_dummy_data_to_client()
            data = self.ssl_socket.recv(4096)

    """Send a random amount of dummy data to the client."""
    def _send_dummy_data_to_client(self):
        # Populate data with a random amount of \x00 bytes.
        data = struct.pack(random.randint(1, MAX_OUTGOING_DATA)*'x')

        # Log it as post-SSL outgoing data.
        self.data['post_ssl_out'].append(data)
        # Send it.
        self.ssl_socket.write(data)

    """Log the client and then close the connection."""
    def _log_client_and_close_conn(self):
        if (self.server.is_only_interested_in_ips()):
            self.server.log('%s:%s' % (self.address, self.port))
        else:
            self._log_client_verbose()

        self._close_conn()

    """Do some verbose client logging."""
    def _log_client_verbose(self):
        """We send our dummy data only after we receive client
        data. This means that the number of bunches of data we have
        sent is less or equal to the number of bunches of data we have
        received."""
        assert(len(self.data['post_ssl_inc']) >= len(self.data['post_ssl_out']))

        # log the IP address
        self.server.log("%s:%s" % (self.address, self.port))

        # log the pre-ssl-handshake data.
        self.server.log("| %s" % (repr(self.data['pre_ssl'][0])))

        # log the application-layer data.
        for i in xrange(len(self.data['post_ssl_inc'])):
            self.server.log("< %s" % (repr(self.data['post_ssl_inc'][i])))
            try:
                self.server.log("> %s" % (repr(self.data['post_ssl_out'][i])))
            except IndexError:
                pass

    """Close the connection."""
    def _close_conn(self):
        if ((self.state == "ST_HANDSHAKED") or
            (self.state == "ST_HANDLED")): # post-SSL-handshake
            assert(self.ssl_socket)
            self.ssl_socket.close()
        elif (self.state == "ST_JUST_CONNECTED"): # pre-SSL-handshake
            assert(not self.ssl_socket)
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
        else:
            assert(False)

"""Custom-made logging level used to log captured data."""
LOGGING_LEVEL_DATA = logging.CRITICAL + 1

"""Represents a hot pot server."""
class Server:
    """Given the 'options' harvested from the argparse module, start
    accepting client connections."""
    def __init__(self, options):
        self.options = options
        self.logger = None # our logger: set in _set_up_logging()


        # Set up the logging subsystem.
        self._set_up_logging()

        # Set up our listener.
        bindsocket = self._fire_up_the_server()

        while True:
            # If we accepted a new client, store the socket in
            # 'newsocket', her address in 'fromaddr' and her port in
            # 'fromport'.
            newsocket, (fromaddr, fromport) = bindsocket.accept()

            # Create a Client object to handle the client.
            Client(self, newsocket, fromaddr, fromport)

    """Sets up the logging subsystem of hot pot."""
    def _set_up_logging(self):
        self.logger = logging.getLogger('data')

        # If there user provided a logfile, use it, otherwise fall
        # back to logging on stdout.
        if (self.options.logfile): # use user's logfile
            log_handler = logging.FileHandler(self.options.logfile)
        else: # else just log to stdout
            log_handler = logging.StreamHandler(sys.stdout)

        formatter = logging.Formatter('%(asctime)s: %(message)s')
        log_handler.setFormatter(formatter)
        self.logger.addHandler(log_handler)

        logging.addLevelName(LOGGING_LEVEL_DATA, "DATA")
        self.logger.setLevel(0)

    """Set up our listener."""
    def _fire_up_the_server(self):
        bindsocket = socket.socket()
        bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # ?
        bindsocket.bind(('', self.options.port))
        bindsocket.listen(5)

        return bindsocket

    """Public: Logging wrapper; used to log client's data."""
    def log(self, string):
        self.logger.log(LOGGING_LEVEL_DATA, string)

    """Public: Return True if we shouldn't send dummy data to clients."""
    def is_laconic(self):
        return self.options.laconic

    """Public: Return True if logging should be restricted to only
    logging IP addresses."""
    def is_only_interested_in_ips(self):
        return self.options.only_ip_addresses

    """Public: Return the filename containing the private key and the
    SSL certificate of the server."""
    def get_ssl_files(self):
        return self.options.ssl_stuff

"""Use the argparse Python module to parse the command line. Return
the user's preferences as an argparse.Namespace."""
def parse_command_line():
    parser = argparse.ArgumentParser(description='')

    parser.add_argument('--port', action="store", dest='port', default=9999,
                        type=int, help="TCP port that we should listen on (default: 1984)")
    parser.add_argument('--ssl_stuff', action='store', dest='ssl_stuff',
                        required=True,
                        help='File containing SSL keys and certificate chain')
    parser.add_argument('--log', action='store', dest='logfile',
                        help='Log file (default: stdout)')
    parser.add_argument('--laconic', dest='laconic', action="store_true",
                        help="Don't send server data (default: off)")
    parser.add_argument('--only_ip_addresses', dest='only_ip_addresses',
                        action="store_true", help="Log only the IP addresses (default: off)")

    options = parser.parse_args()

    assert(options.ssl_stuff) # required=True in argparse
    assert(options.port) # default value

    if (not os.path.isfile(options.ssl_stuff)):
        print "Please provide a valid PEM file."
        sys.exit(1)

    return options

"""Entry function."""
def main():
    # Parse the command line.
    options = parse_command_line()

    # Fire up the server according to the command line options.
    Server(options)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
