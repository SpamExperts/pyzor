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
__revision__ = "$Id: client.py,v 1.9 2002-04-21 22:56:30 ftobin Exp $"


class Client(object):
    __slots__ = ['socket', 'output', 'user', 'auth']
    ttl = 4
    timeout = 4
    max_packet_size = 8192
    user = ''
    auth = ''
    
    def __init__(self, user=None, auth=None):
        if user is not None:
            self.user = user
        if auth is not None:
            self.auth = auth
        self.output = Output()
        self.build_socket()

    def ping(self, address):
        msg = Message()
        msg.add_string(self.user)
        msg.add_string(self.auth)
        msg.add_string('ping')
        thread_id = msg.thread
        self.send(msg, address)
        return self.read_error_code(thread_id)
        
    def report(self, digest, spec, address):
        msg = Message()
        thread_id = msg.thread
        msg.add_string(self.user)
        msg.add_string(self.auth)
        msg.add_string('report')
        msg.add_int(self.ttl)
        msg.add_netenc(spec.netenc())
        msg.add_string(digest)
        self.send(msg, address)
        return self.read_error_code(thread_id)

    def check(self, digest, address):
        msg = Message()
        thread_id = msg.thread
        msg.add_string(self.user)
        msg.add_string(self.auth)
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
        self.expect(fp, proto_name,    read_netstring, "protocol name")
        self.expect(fp, proto_version, read_netstring, "protocol version")

        thread_id = pyzor.ThreadID(read_netint(fp))
        if not thread_id.in_ok_range():
            self.output.warn("received error thread id of %d" % thread_id)
        elif thread_id != expect_id:
            raise ProtocolError, \
                  "received unexpected thread id %d (expected %d)" \
                  % (thread_id, expect_id)

        error_code = read_netint(fp)
        message    = read_netstring(fp)
        return (error_code, message)

    def expect(self, fp, expected, factory, descr=None):
        pyzor.expect(fp, expected, factory, descr)


class ServerList(list):
    inform_url = 'http://pyzor.sourceforge.net/cgi-bin/inform-servers'
    
    def read(self, serverfile):
        for line in serverfile:
            orig_line = line
            line = line.strip()
            if line and not line.startswith('#'):
                self.append(pyzor.Address.from_str(line))


class ExecCall(object):
    __slots__ = ['client', 'servers', 'output']
    
    # hard-coded for the moment
    digest_spec = PiecesDigestSpec([(20, 3), (60, 3)])

    def run(self):
        debug = 0
        (options, args) = getopt.getopt(sys.argv[1:], 'dhc:')
        if len(args) < 1:
           self.usage()

        config_fn = None

        for (o, v) in options:
            if o == '-d':
                debug = 1
            elif o == '-h':
               self.usage()
            elif o == '-c':
                config_fn = v
        
        self.output = Output(debug=debug)

        config = pyzor.Config()
        config.add_section('client')
        config.set('client', 'serversfile',
                   os.path.join(pyzor.get_homedir(), 'servers'))

        if config_fn is None:
            config_fn = pyzor.Config.get_default_filename()
        config.read(config_fn)
        
        servers_fn = config.get_filename('client', 'ServersFile')
    
        homedir = pyzor.get_homedir()
        # We really shouldn't need to make this unless
        # the user wants to use it...
        if not os.path.exists(homedir):
            os.mkdir(homedir)

        command = args[0]
        if not os.path.exists(servers_fn) or command == 'discover':
            sys.stderr.write("downloading servers from %s\n"
                             % ServerList.inform_url)
            download(ServerList.inform_url, servers_fn)
        
        self.servers = ServerList()
        self.servers.read(open(servers_fn))

        if len(self.servers) == 0:
            sys.stderr.write("No servers available!  Maybe try the 'discover' command\n")
            sys.exit(1)

        self.client = Client()

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
        except TimeoutError:
            # note that most of the methods will trap
            # their own timeout error
            sys.stderr.write("timeout from server\n")
            sys.exit(1)

        return

    def usage(self):
        sys.stderr.write("usage: %s [-d] [-c config_file] check|report|discover|ping [cmd_options]\nData is read on standard input.\n"
                         % sys.argv[0])
        sys.exit(1)
        return

    def ping(self, args):
        for server in self.servers:
            try:
                self.output.debug("pinging %s" % str(server))
                result = self.client.ping(server)
            except TimeoutError:
                result = 'timeout'
            sys.stdout.write("%s: %s\n" % (server, result))
        return

    def check(self, args):
        import rfc822
        fp = rfc822.Message(sys.stdin, seekable=0).fp
        
        self.output.debug("digest spec is %s" % self.digest_spec)
        digest = PiecesDigest.compute_from_file(fp,
                                                self.digest_spec,
                                                seekable=0)
        self.output.debug("calculated digest: %s" % digest)

        found_hit = 0
        for server in self.servers:
            try:
                self.output.debug("sending to %s" % str(server))
                result = self.client.check(digest, server)
                if result[0] == 200:
                    output = result[1]
                    if output > 0: found_hit = 1
                else:
                    output = result
            except TimeoutError:
                output = 'timeout'
            sys.stdout.write("%s\t%s\n" % (server, output))
        sys.exit(not found_hit)
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
        self.output.debug("digest spec is %s" % self.digest_spec)
        digest = PiecesDigest.compute_from_file(fp,
                                                self.digest_spec,
                                                seekable=0)
        self.output.debug("calculated digest: %s" % digest)
        for server in self.servers:
            try:
                self.output.debug("sending to %s" % str(server))
                result = self.client.report(digest, self.digest_spec,
                                            server)
            except TimeoutError:
                result = 'timeout'
            sys.stdout.write("%s: %s\n" % (server, result))
        return


def run():
    ExecCall().run()

def timeout(signum, frame):
    raise TimeoutError


def download(url, outfile):
    import urllib
    urllib.urlretrieve(url, outfile)
