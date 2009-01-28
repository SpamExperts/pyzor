"""networked spam-signature detection client"""

import os
import os.path
import socket
import cStringIO
import getopt
import tempfile
import mimetools
import multifile
import sha
import threading

import pyzor
from pyzor import *

__author__   = pyzor.__author__
__version__  = pyzor.__version__
__revision__ = "$Id: client.py,v 1.48 2003-02-01 10:29:42 ftobin Exp $"

randfile = '/dev/random'


class Client(object):
    __slots__ = ['socket', 'output', 'accounts']
    timeout = 5
    max_packet_size = 8192

    def __init__(self, accounts):
        self.accounts = accounts
        self.output   = Output()
        self.build_socket()

    def ping(self, address):
        msg = PingRequest()
        self.send(msg, address)
        return self.read_response(msg.get_thread())

    def info(self, digest, address):
        msg = InfoRequest(digest)
        self.send(msg, address)
        return self.read_response(msg.get_thread())

    def report(self, digest, spec, address):
        msg = ReportRequest(digest, spec)
        self.send(msg, address)
        return self.read_response(msg.get_thread())

    def whitelist(self, digest, spec, address):
        msg = WhitelistRequest(digest, spec)
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
        account = self.accounts[address]

        mac_msg_str = str(MacEnvelope.wrap(account.username,
                                           account.keystuff.key,
                                           msg))
        self.output.debug("sending: %s" % repr(mac_msg_str))
        self.socket.sendto(mac_msg_str, 0, address)

    def recv(self):
        return self.time_call(self.socket.recvfrom,
                              (self.max_packet_size,))

    def time_call(self, call, varargs=(), kwargs=None):
        if kwargs is None:  kwargs  = {}
        timer = threading.Timer(self.timeout, raise_timeout)
        timer.start()
        try:
            return apply(call, varargs, kwargs)
        finally:
            timer.cancel()

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
    inform_url = 'http://pyzor.sourceforge.net/cgi-bin/inform-servers-0-3-x'

    def read(self, serverfile):
        for line in serverfile:
            orig_line = line
            line = line.strip()
            if line and not line.startswith('#'):
                self.append(pyzor.Address.from_str(line))



class ExecCall(object):
    __slots__ = ['client', 'servers', 'output']

    # hard-coded for the moment
    digest_spec = DataDigestSpec([(20, 3), (60, 3)])

    def run(self):
        debug = 0
        log = None
        options = None

        try:
            (options, args) = getopt.getopt(sys.argv[1:], 'dh:',
                                            ['homedir=', 'log', 'help'])
        except getopt.GetoptError:
            self.usage()

        if len(args) < 1:
           self.usage()

        specified_homedir = None

        for (o, v) in options:
            if o == '-d':
                debug = 1
            elif o in ('-h', '--help'):
               self.usage()
            elif o == '--homedir':
                specified_homedir = v
            elif o == '--log':
                log = 1

        self.output = Output(debug=debug)
        homedir = pyzor.get_homedir(specified_homedir)

        if log:
            sys.stderr = open(homedir + "/pyzor.log", 'a')
            sys.stderr.write("\npyzor[" + repr (os.getpid()) + "]:\n")

        config = pyzor.Config(homedir)
        config.add_section('client')

        defaults = {'ServersFile':        'servers',
                    'DiscoverServersURL': ServerList.inform_url,
                    'AccountsFile':       'accounts',
                    'Timeout':            str(Client.timeout),
                    }

        for k, v in defaults.items():
            config.set('client', k, v)

        config.read(os.path.join(homedir, 'config'))

        servers_fn = config.get_filename('client', 'ServersFile')
        Client.timeout = config.getint('client', 'Timeout')

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

        if not self.dispatches.has_key(command):
            self.usage()

        dispatch = self.dispatches[command]
        if dispatch is not None:
            try:
                if not apply(dispatch, (self, args)):
                    sys.exit(1)
            except TimeoutError:
                # note that most of the methods will trap
                # their own timeout error
                sys.stderr.write("timeout from server\n")
                sys.exit(1)


    def usage(self, s=None):
        if s is not None:
            sys.stderr.write("%s\n" % s)
        sys.stderr.write("""
usage: %s [-d] [--homedir dir] command [cmd_opts]
command is one of: check, report, discover, ping, digest, predigest,
                   genkey

Data is read on standard input (stdin).

"""
                         % sys.argv[0])
        sys.exit(2)
        return  # just to help xemacs


    def ping(self, args):
        try:
            getopt.getopt(args[1:], '')
        except getopt.GetoptError:
            self.usage("%s does not take any non-option arguments" % args[0])

        runner = ClientRunner(self.client.ping)

        for server in self.servers:
            runner.run(server, (server,))

        return runner.all_ok


    def info(self, args):
        try:
            (options, args2) = getopt.getopt(args[1:], '', ['mbox'])
        except getopt.GetoptError:
            self.usage("%s does not take any non-option arguments" % args[0])

        do_mbox = 'msg'

        for (o, v) in options:
            if o == '--mbox':
                do_mbox = 'mbox'

        runner = InfoClientRunner(self.client.info)

        for digest in get_input_handler(sys.stdin, self.digest_spec, do_mbox):
            if not digest:
                continue
            for server in self.servers:
                response = runner.run(server, (digest, server))

        return True


    def check(self, args):
        try:
            (options, args2) = getopt.getopt(args[1:], '', ['mbox'])
        except getopt.GetoptError:
            self.usage("%s does not take any non-option arguments" % args[0])

        do_mbox = 'msg'

        for (o, v) in options:
            if o == '--mbox':
                do_mbox = 'mbox'

        runner = CheckClientRunner(self.client.check)

        for digest in get_input_handler(sys.stdin, self.digest_spec, do_mbox):
            if not digest:
                continue
            for server in self.servers:
                runner.run(server, (digest, server))

        return (runner.found_hit and not runner.whitelisted)


    def report(self, args):
        try:
           (options, args2) = getopt.getopt(args[1:], '', ['mbox'])
        except getopt.GetoptError:
            self.usage("%s does not take any non-option arguments" % args[0])

        do_mbox = 'msg'

        for (o, v) in options:
            if o == '--mbox':
                do_mbox = "mbox"

        all_ok = True

        for digest in get_input_handler(sys.stdin, self.digest_spec, do_mbox):
            if not digest:
                continue
            if not self.send_digest(digest, self.digest_spec,
                                    self.client.report):
                all_ok = False

        return all_ok


    def send_digest(self, digest, spec, client_method):
        """digest can be none; if so, nothing is sent"""
        if digest is None:
            return
        typecheck(digest, DataDigest)

        runner = ClientRunner(client_method)

        for server in self.servers:
            runner.run(server, (digest, spec, server))

        return runner.all_ok


    def whitelist(self, args):
        try:
            (options, args2) = getopt.getopt(args[1:], '', ['mbox'])
        except getopt.GetoptError:
            self.usage("%s does not take any non-option arguments" % args[0])

        do_mbox = "msg"

        for (o, v) in options:
            if o == '--mbox':
                do_mbox = "mbox"

        all_ok = True

        for digest in get_input_handler(sys.stdin, self.digest_spec, do_mbox):
            if not digest:
                continue
            if not self.send_digest(digest, self.digest_spec,
                                    self.client.whitelist):
                all_ok = False

        return all_ok


    def digest(self, args):
        try:
           (options, args2) = getopt.getopt(args[1:], '', ['mbox'])
        except getopt.GetoptError:
            self.usage("%s does not take any non-option arguments" % args[0])

        do_mbox = "msg"

        for (o, v) in options:
            if o == '--mbox':
                do_mbox = "mbox"

        for digest in get_input_handler(sys.stdin, self.digest_spec, do_mbox):
            if not digest:
                continue
            sys.stdout.write("%s\n" % digest)

        return True


    def print_digested(self, args):
        try:
            getopt.getopt(args[1:], '')
        except getopt.GetoptError:
            self.usage("%s does not take any non-option arguments" % args[0])

        def loop():
            for digest in get_input_handler(sys.stdin, self.digest_spec):
                pass

        modglobal_apply(globals(), {'DataDigester': PrintingDataDigester},
                        loop)

        return True

    def genkey(self, args):
        try:
            getopt.getopt(args[1:], '')
        except getopt.GetoptError:
            self.usage("%s does not take any non-option arguments" % args[0])

        import getpass
        p1 = getpass.getpass(prompt='Enter passphrase: ')
        p2 = getpass.getpass(prompt='Enter passphrase again: ')
        if p1 != p2:
            sys.stderr.write("Passwords do not match.\n")
            return 0

        del p2

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


    dispatches = {'check':     check,
                  'report':    report,
                  'ping' :     ping,
                  'genkey':    genkey,
                  'info':      info,
                  'whitelist': whitelist,
                  'digest':    digest,
                  'predigest': print_digested,
                  'discover':  None,  # handled earlier
                  }



class DataDigester(object):
    """The major workhouse class"""
    __slots__ = ['_atomic', '_value', '_used_line', '_digest',
                 'seekable']

    # minimum line length for it to be included as part
    # of the digest.  I forget the purpose, however.
    # Someone remind me so I can document it here.
    min_line_length = 8

    # if a message is this many lines or less, then
    # we digest the whole message
    atomic_num_lines = 4

    # We're not going to try to match email addresses
    # as per the spec because it's too freakin difficult
    # Plus, regular expressions don't work well for them.
    # (BNF is better at balanced parens and such)
    email_ptrn = re.compile(r'\S+@\S+')

    # same goes for URL's
    url_ptrn = re.compile(r'[a-z]+:\S+', re.IGNORECASE)

    # We also want to remove anything that is so long it
    # looks like possibly a unique identifier
    longstr_ptrn = re.compile(r'\S{10,}')

    html_tag_ptrn = re.compile(r'<.*?>')
    ws_ptrn       = re.compile(r'\s')

    # we might want to change this in the future.
    # Note that an empty string will always be used to remove whitespace
    unwanted_txt_repl = ''

    def __init__(self, fp, spec, seekable=True):
        self._atomic    = None
        self._value     = None
        self._used_line = None
        self.seekable   = seekable

        (fp, offsets) = self.get_line_offsets(fp)

        # did we get an empty file?
        if len(offsets) == 0:
            return

        self._digest = sha.new()

        if len(offsets) <= self.atomic_num_lines:
            self.handle_atomic(fp)
        else:
            self.handle_pieced(fp, spec, offsets)

        self._value = DataDigest(self._digest.hexdigest())

        assert self._atomic is not None
        assert self._value is not None


    def handle_atomic(self, fp):
        """we digest everything"""
        self._atomic = True
        fp.seek(0)
        for line in fp:
            self.handle_line(line)


    def handle_pieced(self, fp, spec, offsets):
        self._atomic = False
        """digest stuff according to the spec"""
        for (perc_offset, length) in spec:
            assert 0 <= perc_offset < 100

            offset = offsets[int(perc_offset * len(offsets)
                                 / 100.0)]
            fp.seek(offset)

            for i in range(length):
                line = fp.readline()
                if not line:
                    break
                self.handle_line(line)


    def get_line_offsets(self, fp):
        """return tuple of (fp2, line offsets)
        If we are not seekable, fp will be copied into a tempfile,
        and fp2 is hence re-usable.
        If we are not seekable, we also normalize the lines while
        copying them into the tempfile.
        """
        if self.seekable:
            cur_offset = fp.tell()
            newfp = None
        else:
            # we need a seekable file to make
            # line-based skipping around to be more efficient
            # than loading the whole thing into memory
            cur_offset = 0
            newfp = tempfile.TemporaryFile()


        offsets = []

        for line in fp:
            norm = self.normalize(line)
            should_handle = self.should_handle_line(norm)

            if should_handle:
                offsets.append(cur_offset)

            # the thing to remember about cur_offset is that it should
            # be used to specify where to seek to in the
            # 'output' document, not where we currently are in fp
            # Remember, the output document is static if we are seekable
            # (because we don't have to write out a tempfile),
            # but it's *not the same* if we're writing out a new document,
            # since we don't need to write out all the lines.
            moved = 0
            if self.seekable:
                moved = len(line)
            elif should_handle:
                norm += "\n"
                moved = len(norm)
                newfp.write(norm)

            cur_offset += moved

        if not self.seekable:
            fp = newfp

        return (fp, offsets)


    def handle_line(self, line):
        # seekable indicates that
        # the line was not normalized
        # when we first ran over it to get the line offsets
        if self.seekable:
            buf = self.normalize(line)
        else:
            # we at least have to strip the newline
            buf = line.rstrip()
        self._really_handle_buf(buf)

    def _really_handle_buf(self, buf):
        self._digest.update(buf)

    def is_atomic(self):
        if self._atomic is None:
            raise RuntimeError, "digest not calculated yet"
        return bool(self._atomic)

    def get_digest(self):
        return self._value

    def normalize(self, s):
        repl = self.unwanted_txt_repl
        s2 = s
        s2 = self.longstr_ptrn.sub(repl, s2)
        s2 = self.email_ptrn.sub(repl, s2)
        s2 = self.url_ptrn.sub(repl, s2)
        s2 = self.html_tag_ptrn.sub(repl, s2)
        # make sure we do the whitespace last because some of
        # the previous patterns rely on whitespace
        s2 = self.ws_ptrn.sub('', s2)
        return s2
    normalize = classmethod(normalize)

    def should_handle_line(self, s):
        return bool(self.min_line_length <= len(s))
    should_handle_line = classmethod(should_handle_line)



class PrintingDataDigester(DataDigester):
    """extends DataDigester: prints out what we're digesting"""

    def _really_handle_buf(self, buf):
        sys.stdout.write("%s\n" % buf)
        super(PrintingDataDigester, self)._really_handle_buf(buf)



def get_input_handler(fp, spec, style='msg', seekable=False):
    """Return an object that can be iterated over
    to get all the digests from fp according to spec.
    mbox is a boolean"""
    if style == 'msg':
        return filter(lambda x: x is not None,
                      (DataDigester(rfc822BodyCleaner(fp),
                                    spec, seekable).get_digest(),)
                      )

    elif style =='mbox':
        return MailboxDigester(fp, spec)

    elif style == 'digests':
        return JustDigestsIterator(fp)

    raise ValueError, "unknown input style"


class JustDigestsIterator(BasicIterator):
    __slots__ = ['fp']

    def __init__(self, fp):
        self.fp = fp

    def next(self):
        l = fp.readline()
        if not l:
            raise StopIteration
        return l.rstrip()


class MailboxDigester(BasicIterator):
    __slots__ = ['mbox', 'digest_spec', 'seekable']

    def __init__(self, fp, digest_spec, seekable=False):
        import mailbox
        self.mbox        = mailbox.PortableUnixMailbox(fp,
                                                       rfc822BodyCleaner)
        self.digest_spec = digest_spec
        self.seekable    = seekable

    def next(self):
        try:
            next_msg = self.mbox.next()
        except IOError:
            print "Error: Please feed mailbox files in on stdin, i.e."
            print "    pyzor digest --mbox < my_mbox_file"
            next_msg = None
        if next_msg is None:
            raise StopIteration
        return DataDigester(next_msg, self.digest_spec,
                            seekable=self.seekable).get_digest()



class rfc822BodyCleaner(BasicIterator):
    __slots__ = ['fp', 'multifile', 'curfile', 'type']

    def __init__(self, fp):
        msg            = mimetools.Message(fp, seekable=0)
        # Default type is text.  See #1529694.
        self.type      = msg.getmaintype() or "text"
        self.multifile = None
        self.curfile   = None

        if self.type == 'text':
            encoding = msg.getencoding()
            if encoding == '7bit':
                self.curfile = msg.fp
            else:
                import binascii
                self.curfile = tempfile.TemporaryFile()
                try:
                    mimetools.decode(msg.fp, self.curfile, encoding)
                except binascii.Error, e:
                    sys.stderr.write("%s: %s\n" % (e.__class__, e))
                    self.curfile = cStringIO.StringIO()
                except ValueError, e:
                    #sys.stderr.write("%s: %s\n" % (e.__class__, e))
                    self.curfile = msg.fp
                self.curfile.seek(0)

        elif self.type == 'multipart':
            try:
                self.multifile = multifile.MultiFile(msg.fp, seekable=False)
                self.multifile.push(msg.getparam('boundary'))
                self.multifile.next()
                self.curfile = self.__class__(self.multifile)
            except (TypeError, AttributeError, multifile.Error):
                # ignore errors, pass msg as is
                self.curfile = msg.fp


        if self.type == 'text' or self.type == 'multipart':
            assert self.curfile is not None
        else:
            assert self.curfile is None


    def readline(self):
        l = ''
        try:
            if self.type in ('text', 'multipart'):
                l = self.curfile.readline()

            if self.type == 'multipart' and not l and self.multifile.next():
                self.curfile = self.__class__(self.multifile)
                # recursion.  Could get messy if
                # we get a bunch of empty multifile parts
                l = self.readline()
        except (TypeError, AttributeError, multifile.Error):
            pass
        return l


    def next(self):
        try:
            l = self.readline()
        except multifile.Error, e:
            sys.stderr.write("%s: %s\n" % (e.__class__, e))
            raise StopIteration

        if not l:
            raise StopIteration
        return l


class ClientRunner(object):
    __slots__ = ['routine', 'all_ok']

    def __init__(self, routine):
        self.routine = routine
        self.setup()

    def setup(self):
        self.all_ok = True

    def run(self, server, varargs, kwargs=None):
        if kwargs is None:
            kwargs = {}
        message = "%s\t" % str(server)
        response = None
        try:
            response = apply(self.routine, varargs, kwargs)
            self.handle_response(response, message)
        except (CommError, KeyError, ValueError), e:
            sys.stderr.write(message + ("%s: %s\n"
                                        % (e.__class__.__name__, e)))
            self.all_ok = False


    def handle_response(self, response, message):
        """mesaage is a string we've built up so far"""
        if not response.is_ok():
            self.all_ok = False
        sys.stdout.write(message + str(response.head_tuple())
                         + '\n')



class CheckClientRunner(ClientRunner):
    __slots__ = ['found_hit', 'whitelisted']

    # the number of wl-count it takes for the normal
    # count to be overriden
    wl_count_clears = 1

    def setup(self):
        self.found_hit   = False
        self.whitelisted = False
        super(CheckClientRunner, self).setup()

    def handle_response(self, response, message):
        message += "%s\t" % str(response.head_tuple())

        if response.is_ok():
            wl_count = int(response['WL-Count'])
            if wl_count > 0:
                count = 0
                self.whitelisted = True
            else:
                count = int(response['Count'])
                if count > 0:
                    self.found_hit = True

            message += "%d\t%d" % (count, wl_count)
            sys.stdout.write(message + '\n')
        else:
            sys.stderr.write(message)



class InfoClientRunner(ClientRunner):
    def handle_response(self, response, message):
        message += "%s\n" % str(response.head_tuple())

        if response.is_ok():
            count = int(response['Count'])
            message += "\tCount: %d\n" % count

            if count > 0:
                for f in ('Entered', 'Updated', 'WL-Entered', 'WL-Updated'):
                    if response.has_key(f):
                        val = int(response[f])
                        if val == -1:
                            stringed = 'Never'
                        else:
                            stringed = time.ctime(val)

                        # we want to insert the wl-count before
                        # our wl printouts
                        if f is 'WL-Entered':
                            message += ("\tWhiteList Count: %d\n"
                                        % int(response['WL-Count']))

                        message += ("\t%s: %s\n" % (f, stringed))

            sys.stdout.write(message)
        else:
            sys.stderr.write(message)





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
    __slots__ = ['fp', 'lineno', 'output']

    def __init__(self, fp):
        self.fp     = fp
        self.lineno = 0
        self.output = pyzor.Output()

    def __iter__(self):
        return self

    def next(self):
        while 1:
            orig_line = self.fp.readline()
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


def raise_timeout():
    raise TimeoutError


def download(url, outfile):
    import urllib
    urllib.urlretrieve(url, outfile)
