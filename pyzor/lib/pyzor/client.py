"""networked spam-signature detection client"""

# Copyright (C) 2002 Frank J. Tobin <ftobin@neverending.org>
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, visit the following URL:
# http://www.gnu.org/copyleft/gpl.html

import os
import os.path
import socket
import signal
import StringIO
import getopt

import pyzor
from pyzor import *

__author__   = pyzor.__author__
__version__  = pyzor.__version__
__revision__ = "$Id: client.py,v 1.7 2002-04-16 18:02:04 ftobin Exp $"


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
        
        address = fields[1].split(':')
        if len(address) != 2:
            raise ConfigError, "invalid address; must be of form ip:port"
        
        (ip, port) = address
        try:
            port = int(port)
        except ValueError, e:
            raise ConfigError, "%s is not a valid port" % repr(port)
        self.output.debug("loading in server %s" % str((ip, port)))
        self.servers.append((ip, port))


class ExecCall(object):
    __slots__ = ['client', 'config']
    # hard-coded for the moment
    digest_spec = PiecesDigestSpec([(20, 3), (60, 3)])

    def run(self):
        debug = 0
        (options, args) = getopt.getopt(sys.argv[1:], 'dh')
        if len(args) < 1:
           self.usage()

        for (o, v) in options:
            if o == '-d':
                debug = 1
            elif o == '-h':
               self.usage()
    
        command = args[0]
    
        self.client = Client(debug=debug)
        
        self.config = Config()
        config_fn = self.config.get_default_filename()
        
        if not os.path.exists(config_fn) or command == 'discover':
            self.discover(args)
        self.config.load(config_fn)

        if len(self.config.servers) == 0:
            sys.stderr.write("No servers available!  Maybe try the 'discover' command\n")
            sys.exit(1)

        try: 
            if command == 'discover':
                # already completed above
                pass
            elif command == 'check':
                self.check(args)
            elif command == 'report':
                self.report(args)
            elif command == 'ping':
                self.ping(args)
            else:
               self.usage()
        except TimeoutError, e:
            sys.stderr.write("timeout from server\n")
            sys.exit(1)

        return

    def usage(self):
        sys.stderr.write("usage: %s [-d] check|report|discover|ping [cmd_options]\nData is read on standard input.\n"
                         % sys.argv[0])
        sys.exit(1)
        return

    def discover(self, args):
        self.config.get_informed(self.config.default_inform_url, config_fn)
        return
    
    def ping(self, args):
        print repr(self.client.ping(self.config.servers[0]))
        return

    def check(self, args):
        import rfc822
        fp = rfc822.Message(sys.stdin, seekable=0).fp
        
        digest = PiecesDigest.compute_from_file(fp,
                                                self.digest_spec,
                                                seekable=0)

        result = self.client.check(digest, self.config.servers[0])
        if result[0] == 200:
            print result[1]
            sys.exit(result[1] == 0)
        sys.exit(1)
        return

    def report(self, args):
        (options, args2) = getopt.getopt(args[1:], '', ['mbox'])
        do_mbox = 0
        for (o, v) in options:
            if o == '--mbox':
                do_mbox = 1
                
        if do_mbox:
            import mailbox
            mbox = mailbox.PortableUnixMailbox(sys.stdin)
            for msg in mbox:
                self.report_fp(msg.fp)
        else:
            import rfc822
            self.report_fp(rfc822.Message(sys.stdin).fp)
        return


    def report_fp(self, fp):
        digest = PiecesDigest.compute_from_file(fp,
                                                self.digest_spec,
                                                seekable=0)

        print repr(self.client.report(digest, self.digest_spec,
                                      self.config.servers[0]))
        return


def run():
    ExecCall().run()

def timeout(signum, handler):
    raise TimeoutError
