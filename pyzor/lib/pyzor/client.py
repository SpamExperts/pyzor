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
import cStringIO
import getopt

import pyzor
from pyzor import *

__author__   = pyzor.__author__
__version__  = pyzor.__version__
__revision__ = "$Id: client.py,v 1.13 2002-05-08 03:26:23 ftobin Exp $"


class Client(object):
    __slots__ = ['socket', 'output', 'user', 'auth']
    ttl = 4
    timeout = 4
    max_packet_size = 8192
    user     = ''
    user_key = ''
    
    def __init__(self, user=None, auth=None):
        if user is not None:
            self.user = user
        if auth is not None:
            self.auth = auth
        self.output = Output()
        self.build_socket()

    def ping(self, address):
        msg = PingRequest()
        self.send(msg, address)
        return self.read_response(msg.get_thread())
        
    def report(self, digest, spec, address):
        msg = ReportRequest(digest, spec)
        self.send(msg, address)
        return self.read_response(msg.get_thread())

    def check(self, digest, address):
        msg = CheckRequest(digest)
        self.send(msg, address)
        return self.read_response(msg.get_thread())

    def build_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, msg, address):
        msg.init_for_sending()
        mac_msg_str = str(MacEnvelope.wrap(self.user, self.user_key, msg))
        self.output.debug("sending: %s" % repr(mac_msg_str))
        self.socket.sendto(mac_msg_str, 0, address)

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

    def read_response(self, expect_id):
        (packet, address) = self.recv()
        self.output.debug("received: %s" % repr(packet))
        msg = Response(cStringIO.StringIO(packet))

        msg.ensure_complete()

        try:
            thread_id = msg.get_thread()
            if thread_id != expect_id:
                raise ProtocolError, \
                      "received unexpected thread id %d (expected %d)" \
                      % (thread_id, expect_id)
        except KeyError:
            self.output.warn("no thread id received")

        return msg



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

        defaults = {'serversfile': os.path.join(pyzor.get_homedir(),
                                                'servers'),
                    'DiscoverServersURL': ServerList.inform_url
                    }

        for k, v in defaults.items():
            config.set('client', k, v)
            
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
                             % config.get('client', 'DiscoverServersURL'))
            download(config.get('client', 'DiscoverServersURL'), servers_fn)
        
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
            self.output.debug("pinging %s" % str(server))
            message = "%s\t" % str(server)
            try:
                response = self.client.ping(server)
                sys.stdout.write(message + str(response.head_tuple())
                                 + '\n')
            except TimeoutError:
                sys.stderr.write(message + 'timeout\n')
        return

    def check(self, args):
        import rfc822
        fp = rfc822.Message(sys.stdin, seekable=False).fp
        
        self.output.debug("digest spec is %s" % self.digest_spec)
        digest = PiecesDigest.compute_from_file(fp,
                                                self.digest_spec,
                                                seekable=False)
        if digest is None:
            return
        
        self.output.debug("calculated digest: %s" % digest)

        found_hit = False
        for server in self.servers:
            self.output.debug("sending to %s" % str(server))
            message = "%s\t" % str(server)
            try:
                response = self.client.check(digest, server)
                message += "%s\t" % str(response.head_tuple())

                if response.is_ok():
                    if not response.has_key('Count'):
                        raise IncompleteMessageError, "no count received"
                    count = int(response['Count'])

                    if count > 0:
                        found_hit = True
                    message += str(count)
                sys.stdout.write(message + '\n')
                
            except TimeoutError:
                sys.stderr.write(message + 'timeout\n')
            except IncompleteMessageError, e:
                sys.stderr.write(message + 'incomplete response: '
                                 + str(e) + '\n')

        # return 'success', 0, if we found a hit.
        sys.exit(bool(not found_hit))
        return

    def report(self, args):
        (options, args2) = getopt.getopt(args[1:], '', ['mbox'])
        do_mbox = False

        for (o, v) in options:
            if o == '--mbox':
                do_mbox = True
                
        self.output.debug("digest spec is %s" % self.digest_spec)

        if do_mbox:
            import mailbox
            mbox = mailbox.PortableUnixMailbox(sys.stdin)
            for digest in MailboxDigester(mbox, self.digest_spec):
                if digest is not None:
                    self.report_digest(digest)
        else:
            import rfc822
            digest = PiecesDigest.compute_from_file(rfc822.Message(sys.stdin).fp,
                                                    self.digest_spec,
                                                    seekable=False)
            if digest is not None:
                self.report_digest(digest)
        return


    def report_digest(self, digest):
        assert isinstance(digest, PiecesDigest)

        self.output.debug("calculated digest: %s" % digest)
        
        for server in self.servers:
            message = "%s\t" % str(server)
            self.output.debug("sending to %s" % str(server))
            try:
                response = self.client.report(digest, self.digest_spec,
                                              server)
                sys.stdout.write(message + str(response.head_tuple()) + '\n')
            except IncompleteMessageError, e:
                sys.stderr.write(message + 'incomplete response: '
                                 + str(e) + '\n')
            except TimeoutError:
                sys.stderr.write(message + 'timeout\n')
        return


class MailboxDigester(object):
    __slots__ = ['mbox', 'digest_spec']
    
    def __init__(self, mbox, digest_spec):
        self.mbox = mbox
        self.digest_spec = digest_spec

    def __iter__(self):
        return self

    def next(self):
        next_msg = self.mbox.next()
        if next_msg is None:
            raise StopIteration
        return PiecesDigest.compute_from_file(next_msg.fp,
                                              self.digest_spec,
                                              seekable=False)


def run():
    ExecCall().run()

def timeout(signum, frame):
    raise TimeoutError


def download(url, outfile):
    import urllib
    urllib.urlretrieve(url, outfile)
