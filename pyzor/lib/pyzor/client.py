"""networked spam-signature detection client

Copyright (C) 2000 Frank J. Tobin <ftobin@neverending.org>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, visit the following URL:
http://www.gnu.org/copyleft/gpl.html
"""

import os
import os.path
import socket
import signal
import StringIO

import pyzor
from pyzor import *

__author__   = pyzor.__author__
__version__  = pyzor.__version__
__revision__ = "$Id"


class ConfigError(Exception):
    pass

class Client(object):
    __slots__ = ['socket', 'output']
    ttl = 4
    timeout = 4
    max_packet_size = 8192
    
    def __init__(self, debug):
        self.output = Output(debug=debug)
        self.build_socket()

    def ping(self, address):
        msg = Message()
        msg.add_string('ping')
        thread_id = msg.thread
        self.send(msg, address)
        return self.read_error_code(thread_id)
        
    def report(self, digest, spec, address):
        msg = Message()
        thread_id = msg.thread
        msg.add_string('report')
        msg.add_int(self.ttl)
        msg.add_netenc(spec.netenc())
        msg.add_string(digest)
        self.send(msg, address)
        return self.read_error_code(thread_id)

    def check(self, digest, address):
        msg = Message()
        thread_id = msg.thread
        msg.add_string('check')
        msg.add_int(self.ttl)
        msg.add_string(digest)
        self.send(msg, address)
        return self.read_error_code(thread_id)

    def build_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, msg, address):
        self.output.debug("sending: %s" % repr(str(msg)))
        self.socket.sendto(str(msg), 0, address)

    def recv(self):
        return self.time_call(self.socket.recvfrom, (self.max_packet_size,))

    def time_call(self, call, varargs=(), kwargs=None):
        if kwargs is None:  kwargs  = {}
        saved_handler = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM, timeout)
        signal.alarm(self.timeout)
        try:
            return apply(call, varargs, kwargs)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, saved_handler)

    def read_error_code(self, expect_id):
        (packet, address) = self.recv()
        self.output.debug("received: %s" % repr(packet))
        fp = StringIO.StringIO(packet)
        self.expect(fp, proto_name,    read_netstring)
        self.expect(fp, proto_version, read_netstring)
        self.expect(fp, expect_id,     read_netint)

        error_code = read_netint(fp)
        message    = read_netstring(fp)
        return (error_code, message)

    def expect(self, fp, expected, factory):
        got = apply(factory, (fp,))
        if got != expected:
            raise ProtocolError, \
                  "expected %s, got %s" % (repr(expected), repr(got))


class Config(object):
    __slots__ = ['servers', 'output']
    config_basename    = '.pyzor'
    default_inform_url = 'http://pyzor.sourceforge.net/cgi-bin/inform'
    
    def __init__(self):
        self.output = Output()
        self.servers = []

    def get_default_filename(self):
        homedir = os.getenv('HOME')
        if homedir is None:
            raise RuntimeError, "no HOME environment variable set"

        return os.path.join(homedir, self.config_basename)
    
    def get_informed(self, url, outfile):
        import urllib
        self.output.debug("retrieving servers from %s" % url)
        urllib.urlretrieve(url, outfile)

    def load(self, configfile):
        cf = open(configfile)
        for line in cf:
            orig_line = line
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            fields = line.split()
            try:
                if fields[0] == 'server':
                    self.handle_server(fields)
                else:
                    raise ConfigError, \
                          "invalid setting %s" % repr(fields[0])

            except ConfigError, e:
                self.output.warn("%s is not a valid config line: %s"
                                 % (repr(orig_line), e))
                
    def handle_server(self, fields):
        if len(fields) != 2:
            raise ConfigError, "invalid number of fields"
        
        (ip, port) = fields[1].split(':')
        try:
            port = int(port)
        except ValueError, e:
            raise ConfigError, "%s is not a valid port" % repr(port)
        self.output.debug("loading in server %s" % str((ip, port)))
        self.servers.append((ip, port))


def timeout(signum, handler):
    raise TimeoutError

