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
__revision__ = "$Id: client.py,v 1.17 2002-06-17 17:18:08 ftobin Exp $"

randfile = '/dev/random'


class Client(object):
    __slots__ = ['socket', 'output', 'accounts']
    ttl = 4
    timeout = 4
    max_packet_size = 8192
    
    def __init__(self, accounts):
        self.accounts = accounts
        self.output   = Output()
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

    def shutdown(self, address):
        msg = ShutdownRequest()
        self.send(msg, address)
        return self.read_response(msg.get_thread())

    def build_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, msg, address):
        msg.init_for_sending()
        account = self.accounts[address]
        
        mac_msg_str = str(MacEnvelope.wrap(account.username,
                                           account.keystuff.key,
                                           msg))
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
                if thread_id.in_ok_range():
                    raise ProtocolError, \
                          "received unexpected thread id %d (expected %d)" \
                          % (thread_id, expect_id)
                else:
                    self.output.warn("received error thread id %d (expected %d)"
                                     % (thread_id, expect_id))
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

        defaults = {'ServersFile': os.path.join(pyzor.get_homedir(),
                                                'servers'),
                    'DiscoverServersURL': ServerList.inform_url,
                    'AccountsFile' : os.path.join(pyzor.get_homedir(),
                                                  'accounts'),
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


        self.servers  = self.get_servers(servers_fn)
        self.client = Client(self.get_accounts(config.get_filename('client',
                                                                   'AccountsFile')))

        routines = {'check':    self.check,
                    'report':   self.report,
                    'ping' :    self.ping,
                    'genkey':   self.genkey,
                    'shutdown': self.shutdown,
                    'discover': None         # already completed above
                    }

        if not routines.has_key(command):
            self.usage()

        routine = routines[command]
        if routine is not None:
            try:
                if not apply(routine, (args,)):
                    sys.exit(1)
            except TimeoutError:
                # note that most of the methods will trap
                # their own timeout error
                sys.stderr.write("timeout from server\n")
                sys.exit(1)


    def usage(self):
        sys.stderr.write("usage: %s [-d] [-c config_file] check|report|discover|ping|genkey|shutdown [cmd_options]\nData is read on standard input.\n"
                         % sys.argv[0])
        sys.exit(1)
        return  # just to help xemacs


    def ping(self, args):
        (options, args2) = getopt.getopt(args[1:], '')
        iterator = StdClientIterator(self.client.ping)

        for server in self.servers:
            iterator.run(server, (server,))

        return iterator.all_ok
        

    def shutdown(self, args):
        (options, args2) = getopt.getopt(args[1:], '')

        iterator = StdClientIterator(self.client.shutdown)

        for arg in args2:
            server = Address.from_str(arg)
            iterator.run(server, (server,))
                    
        return iterator.all_ok


    def check(self, args):
        (options, args2) = getopt.getopt(args[1:], '')

        import rfc822
        fp = rfc822.Message(sys.stdin, seekable=False).fp
        
        self.output.debug("digest spec is %s" % self.digest_spec)
        digest = PiecesDigest.compute_from_file(fp,
                                                self.digest_spec,
                                                seekable=False)
        if digest is None:
            return
        
        self.output.debug("calculated digest: %s" % digest)

        iterator = CheckClientIterator(self.client.check)
        
        for server in self.servers:
            response = iterator.run(server, (digest, server))

        return iterator.found_hit


    def report(self, args):
        (options, args2) = getopt.getopt(args[1:], '', ['mbox'])
        do_mbox = False

        for (o, v) in options:
            if o == '--mbox':
                do_mbox = True
                
        self.output.debug("digest spec is %s" % self.digest_spec)
        all_ok = True

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
                if not self.report_digest(digest):
                    all_ok = False
        
        return all_ok


    def report_digest(self, digest):
        typecheck(digest, PiecesDigest)

        self.output.debug("calculated digest: %s" % digest)

        iterator = StdClientIterator(self.client.report)

        for server in self.servers:
            iterator.run(server, (digest, self.digest_spec, server))
        
        return iterator.all_ok


    def genkey(self, args):
        (options, args2) = getopt.getopt(args[1:], '')

        import getpass
        p1 = getpass.getpass(prompt='Enter passphrase: ')
        p2 = getpass.getpass(prompt='Enter passphrase again: ')
        if p1 != p2:
            sys.stderr.write("Passwords do not match.\n")
            return 0

        del p2

        import sha
        saltfile = open(randfile)
        salt = saltfile.read(sha.digest_size)
        del saltfile

        salt_digest = sha.new(salt)

        pass_digest = sha.new()
        pass_digest.update(salt_digest.digest())
        pass_digest.update(p1)
        sys.stdout.write("salt,key:\n")
        sys.stdout.write("%s,%s\n" % (salt_digest.hexdigest(),
                                      pass_digest.hexdigest()))

        return True


    def get_servers(servers_fn):
        servers = ServerList()
        servers.read(open(servers_fn))

        if len(servers) == 0:
            sys.stderr.write("No servers available!  Maybe try the 'discover' command\n")
            sys.exit(1)
        return servers

    get_servers = staticmethod(get_servers)


    def get_accounts(accounts_fn):
        accounts = AccountsDict()
        if os.path.exists(accounts_fn):
            for address, account in AccountsFile(open(accounts_fn)):
                accounts[address] = account
        return accounts

    get_accounts = staticmethod(get_accounts)



class StdClientIterator(object):
    __slots__ = ['routine', 'all_ok']
    
    def __init__(self, routine):
        self.routine = routine
        self.all_ok = True

    def run(self, server, varargs, kwargs=None):
        if kwargs is None:
            kwargs = {}
        message = "%s\t" % str(server)
        response = None
        try:
            response = apply(self.routine, varargs, kwargs)
            self.handle_response(response, message)
        except CommError, e:
            sys.stderr.write(message + ("%s: %s\n"
                                        % (e.__class__.__name__, e)))
            self.all_ok = False
        
    def handle_response(self, response, message):
        """mesaage is a string we've built up so far"""
        if not response.is_ok():
            self.all_ok = False
        sys.stdout.write(message + str(response.head_tuple())
                         + '\n')
    

class CheckClientIterator(StdClientIterator):
    __slots__ = ['found_hit']
    def __init__(self, routine):
        self.found_hit = False
        super(CheckClientIterator, self).__init__(routine)
    
    def handle_response(self, response, message):
        message += "%s\t" % str(response.head_tuple())
        
        if response.is_ok():
            if not response.has_key('Count'):
                raise IncompleteMessageError, "no count received"

            count = int(response['Count'])
            if count > 0:
                self.found_hit = True
            
            message += str(count)
            sys.stdout.write(message + '\n')
        else:
            sys.stderr.write(message)


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



class Account(tuple):
    def __init__(self, v):
        self.validate()

    def validate(self):
        typecheck(self.username, pyzor.Username)
        typecheck(self.keystuff, Keystuff)

    def username(self):
        return self[0]
    username = property(username)

    def keystuff(self):
        return self[1]
    keystuff = property(keystuff)



class Keystuff(tuple):
    """tuple of (salt, key).  Each is a long.
    One or the other may be None, but not both."""
    def __init__(self, v):
        self.validate()

    def validate(self):
        # When we support just leaving the salt in, this should
        # be removed
        if self[1] is None:
            raise ValueError, "no key information"
        
        for x in self:
            if not (isinstance(x, long) or x is None):
                raise ValueError, "Keystuff must be long's or None's"

        # make sure we didn't get all None's
        if not filter(lambda x: x is not None, self): 
            raise ValueError, "keystuff can't be all None's"

    def from_hexstr(self, s):
        parts = s.split(',')
        if len(parts) != 2:
            raise ValueError, "invalid number of parts for keystuff; perhaps you forgot comma at beginning for salt divider?"
        return self(map(self.hex_to_long, parts))
    from_hexstr = classmethod(from_hexstr)

    def hex_to_long(h):
        """Allows the argument to be an empty string"""
        if h is '':
            return None
        return long(h, 16)
    hex_to_long = staticmethod(hex_to_long)

    def salt(self):
        return self[0]
    salt = property(salt)

    def key(self):
        return self[1]
    key = property(key)



class AccountsDict(dict):
    """Key is pyzor.Address, value is Account
    When getting, defaults to anonymous_account"""
    
    anonymous_account = Account((pyzor.anonymous_user,
                                 Keystuff((None, 0L))))
    
    def __setitem__(self, k, v):
        typecheck(k, pyzor.Address)
        typecheck(v, Account)
        super(AccountsDict, self).__setitem__(k, v)

    def __getitem__(self, k):
        try:
            return super(AccountsDict, self).__getitem__(k)
        except KeyError:
            return self.anonymous_account



class AccountsFile(object):
    """Iteration gives a tuple of (Address, Account)

    Layout of file is:
    host : port ; username : keystuff
    """
    __slots__ = ['file', 'lineno', 'output']
    
    def __init__(self, f):
        self.file = f
        self.lineno = 0
        self.output = pyzor.Output()

    def __iter__(self):
        return self

    def next(self):
        while 1:
            orig_line = self.file.readline()
            self.lineno += 1
            
            if not orig_line:
                raise StopIteration
            line = orig_line.strip()
            if not line or line.startswith('#'):
                continue
            fields = line.split(':')
            fields = map(lambda x: x.strip(), fields)
            
            if len(fields) != 4:
                self.output.warn("account file: invalid line %d: wrong number of parts"
                                 % self.lineno)
                continue

            try:
                return (pyzor.Address((fields[0], int(fields[1]))),
                        Account((Username(fields[2]),
                                 Keystuff.from_hexstr(fields[3]))))
            except ValueError, e:
                self.output.warn("account file: invalid line %d: %s"
                                 % (self.lineno, e))



def run():
    ExecCall().run()


def timeout(signum, frame):
    raise TimeoutError


def download(url, outfile):
    import urllib
    urllib.urlretrieve(url, outfile)
