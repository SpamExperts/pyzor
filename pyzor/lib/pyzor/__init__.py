"""networked spam-signature detection

CLIENT (pyzor):

usage: pyzor [-d] [-c config] check|report|discover|ping [cmd_options]

options:

-d:
    turn on debugging

-c config:
    use file 'config' instead of the default ~/.pyzor/config.


commands:

check:
    Reads on standard input an rfc822 (email) message.
    Exit code is zero (0) if and only if a match is found.

    If multiple servers are listed in the configuration file,
    the exit code will be zero (0) if and only if there
    is a match found on at least one server.


report [--mbox]:
    Reads on standard input an RFC 822 (mail) message.
    Sends to the server a digest of each message
    in the mailbox.  Writes to standard output
    a tuple of (error-code, message) from the server.

    If --mbox is provided, then the input is assumed
    to be a unix mailbox, and all messages in it
    will be sent to the server.


discover:
    Finds Pyzor servers, and writes them to ~/.pyzor.
    This may accomplished through querying already-known
    servers or an HTTP call to a hard-coded address.


ping:
    Merely requests a response from the server.


Using Pyzor in procmail:

To use pyzor in a procmail system, consider the following
simple recipe:

:0 Wc
| pyzor check
:0 a
pyzor-caught

Or, to add merely add header:

:0 Wc
| pyzor check
:0 Waf
| formail -A 'X-Pyzor: spam'


Differences from Razor clients:
    Pyzor does not consult a white-list for you.  This
    is best handled by other systems, such as other
    procmail rules.

Using pyzor with ReadyExec:
    ReadyExec is a system to eliminate the high startup-cost
    of executing scripts repeatedly.  If you execute
    pyzor a lot, you might be interested in installing
    ReadyExec and using it with pyzor.  You can
    get ReadyExec from http://readyexec.sourceforge.net/

    To use pyzor with ReadyExec, the readyexecd.py server
    needs to be started as:
    
        readyexecd.py <sock_file> pyzor.client.run

    Individual clients are then executed as:
        readyexec <sockfile> report
    or
        readyexec <sockfile> check
    etc.


SERVER (pyzord):

usage: pyzord [-d] dbfile port

-d:
    turn on debugging

dbfile:
    where the database should be kept

port:
    port to listen on


Sending a USR1 signal to the server process will result
in it cleaning out digests not updated within the last 48 hours.


FILES:

~/pyzor/config:
    Format is INI-style (name=value, divided into [section]'s).
    All filenames can have shell-style ~'s in them.
    Defaults are shown below.

    [client]
      ServersFile = ~/.pyzor/servers
          Location of file which contains a list of servers,
          host:ip per line

      DiscoverServersURL = http://pyzor.sourceforge.net/cgi-bin/inform-servers
          URL to discover servers from.

    [server]
      Port=24441
          Port to listen on.

      ListenAddress = 0.0.0.0
          Address to listen on.

      LogFile = ~/.pyzor/pyzord.log
          Location of logfile. Logfile format:
              epochtime,user,address,command,data

      PidFile = ~/.pyzor/pyzord.pid
          Location of file containing PID of server.

      DigestDB = ~/.pyzor/pyzord.db
          Location of digest database.

      CleanupAge = 259200
          When cleaning the database, entries older than this number
          of seconds are removed.


TODO:
    The portions of mail which are digested should be dynamic.

    P2P between servers.


Copyright (C) 2002 Frank J. Tobin <ftobin@neverending.org>

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

__author__   = "Frank J. Tobin, ftobin@neverending.org"
__version__  = "0.2.0"
__revision__ = "$Id: __init__.py,v 1.17 2002-05-17 20:58:15 ftobin Exp $"

import os
import os.path
import re
import sys
import sha
import tempfile
import random
import ConfigParser
import rfc822
import cStringIO
import time

proto_name     = 'pyzor'
proto_version  =  2.0
anonymous_user = 'anonymous'

class ProtocolError(Exception):
    pass

class TimeoutError(Exception):
    pass

class IncompleteMessageError(ProtocolError):
    pass

class UnsupportedVersionError(ProtocolError):
    pass

class SignatureError(Exception):
    """unknown user, signature on msg invalid,
    or not within allowed time range"""
    pass


class Singleton(object):
    __slots__ = []
    def __new__(cls, *args, **kwds):
        it = cls.__dict__.get('__it__')
        if it is None:
            cls.__it__ = object.__new__(cls)
        return cls.__it__


class Username(str):
    user_pattern = re.compile(r'^[-\.\w]+$')
    
    def __init__(self, s):
        super(Username, self).__init__(s)
        self.validate()

    def validate(self):
        if not self.user_patter.match(self):
            raise ValueError, "%s is an invalid username" % self


class Opname(str):
    op_pattern = re.compile(r'^[-\.\w]+$')
    
    def __init__(self, s):
        super(Username, self).__init__(s)
        self.validate()

    def validate(self):
        if not self.user_patter.match(self):
            raise ValueError, "%s is an invalid username" % self


class Output(Singleton):
    do_debug = False
    quiet    = False
    def __init__(self, quiet=None, debug=None):
        if quiet is not None: self.quiet = quiet
        if debug is not None: self.do_debug = debug
    def data(self, msg):
        print msg
    def warn(self, msg):
        if not self.quiet: sys.__stderr__.write('%s\n' % msg)
    def debug(self, msg):
        if self.do_debug: sys.__stderr__.write('%s\n' % msg)


class PiecesDigest(str):
    # hex output doubles digest size
    value_size = sha.digest_size * 2
    
    bufsize = 1024

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
    
    ws_ptrn = re.compile(r'\s')

    def __init__(self, value):
        if len(value) != self.value_size:
            raise ValueError, "invalid digest value size"
        super(PiecesDigest, self).__init__(value)

    def get_line_offsets(buf):
        cur_offset = 0
        offsets = []
        while 1:
            i = buf.find('\n', cur_offset)
            if i == -1:
                return offsets
            offsets.append(i)
            cur_offset = i + 1
            
    get_line_offsets = staticmethod(get_line_offsets)

    def normalize(self, s):
        s2 = s
        s2 = self.email_ptrn.sub('', s2)
        s2 = self.url_ptrn.sub('', s2)
        s2 = self.longstr_ptrn.sub('', s2)
        # make sure we do the whitespace last because some of
        # the previous patterns rely in whitespace
        s2 = self.ws_ptrn.sub('', s2)
        return s2
    
    normalize = classmethod(normalize)

    def compute_from_file(self, fp, spec, seekable=1):
        line_offsets = []

        if seekable:
            cur_offset = fp.tell()
            newfp = None
        else:
            # we need a seekable file because to make
            # line-based skipping around to be more efficient
            # than loading the whole thing into memory
            cur_offset = 0
            newfp = tempfile.TemporaryFile()

        while 1:
            buf = fp.read(self.bufsize)
            line_offsets.extend(map(lambda x: cur_offset + x,
                                    self.get_line_offsets(buf)))
            if not buf: break
            cur_offset += len(buf)
            
            if newfp:
                newfp.write(buf)

        if newfp:
            fp = newfp

        # did we get an empty file?
        if not line_offsets:
            return None
            
        digest = sha.new()
        
        for (perc_offset, length) in spec:
            assert 0 <= perc_offset < 100

            offset = line_offsets[int(perc_offset/100 * len(line_offsets))]
            fp.seek(offset)

            i = 0
            while i < length:
                line = fp.readline()
                if not line: break
                norm_line = self.normalize(line)
                if not norm_line: continue
                digest.update(norm_line)
                i += 1

        return apply(self, (digest.hexdigest(),))
    
    compute_from_file = classmethod(compute_from_file)


class PiecesDigestSpec(list):
    """a list of tuples, (perc_offset, length)"""

    def validate(self):
        for t in self:
            self.validate_tuple(t)

    def validate_tuple(t):
        (perc_offset, length) = t
        if not (0 <= perc_offset < 100):
            raise ValueError, "offset percentage out of bounds"
        if not length > 0:
            raise ValueError, "piece lengths must be positive"
        
    validate_tuple = staticmethod(validate_tuple)

    def netstring(self):
        # flattened, commified
        return ','.join(map(str, reduce(lambda x, y: x + y, self, ())))

    def from_netstring(self, s):
        new_spec = apply(self)

        expanded_list = s.split(',')
        if len(extended_list) % 2 != 0:
            raise ValueError, "invalid list parity"

        for i in range(0, len(expanded_list), 2):
            perc_offset = int(expanded_list[i])
            length      = int(expanded_list[i+1])

            self.validate_tuple(perc_offset, length)
            new_spec.append((perc_offset, length))
            
        return new_spec

    from_netstring = classmethod(from_netstring)


class Message(rfc822.Message, object):
    def __init__(self, fp=None):
        if fp is None:
            fp = cStringIO.StringIO()
            
        super(Message, self).__init__(fp)

    def init_for_sending(self):
        if __debug__:
            self.ensure_complete()

    def __str__(self):
        s = ''.join(self.headers)
        s += '\n'
        self.rewindbody()

        # okay to slurp since we're dealing with UDP
        s += self.fp.read()

        return s

    def __nonzero__(self):
        # just to make sure some old code doesn't try to use this
        raise NotImplementedError

    def ensure_complete(self):
        pass


class ThreadedMessage(Message):
    def init_for_sending(self):
        if not self.has_key('Thread'):
            self.set_thread(ThreadId.generate())
        assert self.has_key('Thread')

        self.setdefault('PV', str(proto_version))
        super(ThreadedMessage, self).init_for_sending()
        
    def ensure_complete(self):
        if not (self.has_key('PV') and self.has_key('Thread')):
            raise IncompleteMessageError, \
                  "doesn't have fields for a ThreadedMessage"
        super(ThreadedMessage, self).ensure_complete()
    
    def get_protocol_version(self):
        return float(self['PV'])

    def get_thread(self):
        return ThreadId(self['Thread'])

    def set_thread(self, i):
        assert isinstance(i, ThreadId)
        self['Thread'] = str(i)



class MacEnvelope(Message):
    ts_diff_max = 180
    
    def ensure_complete(self):
        if not (self.has_key('User')
                and self.has_key('Time')
                and self.has_key('Sig')):
             raise IncompleteMessageError, \
                   "doesn't have fields for a MacEnvelope"
        super(MacEnvelope, self).ensure_complete()

    def get_submsg(self, factory=ThreadedMessage):
        self.rewindbody()
        return apply(factory, (self.fp,))
    
    def verify_sig(self, user_key):
        assert isinstance(user_key, str)
        
        user     = self['User']
        ts       = int(self['Time'])
        said_sig = self['Sig']

        if abs(time.time() - ts) > self.ts_diff_max:
            raise SignatureError, "timestamp not within allowed range"

        msg = self.get_submsg()

        calc_sig = self.sign_msg(user_key, ts, msg).hexdigest()

        if not (calc_sig == said_sig):
            raise SignatureError, "invalid signature"

    def wrap(self, user, hashed_key, msg):
        """This should be used to create a MacEnvelope

        hashed_key is H(U + ':' + P)"""
        
        assert isinstance(user, str)
        assert isinstance(msg, Message)
        assert isinstance(hashed_key, str)

        env = apply(self)
        ts = int(time.time())

        env['User'] = user
        env['Time'] = str(ts)
        env['Sig'] = self.sign_msg(hashed_key, ts, msg).hexdigest()

        env.fp.write(str(msg))

        return env

    wrap = classmethod(wrap)


    def hash_msg(msg):
        """returns a digest object"""
        assert isinstance(msg, Message)
        h = sha.new()
        h.update(str(msg))
        return h

    hash_msg = staticmethod(hash_msg)


    def sign_msg(self, hashed_key, ts, msg):
        """ts is timestamp for message (epoch seconds)

        S = H (H(M) + T + K)
        M is message
        T is timestamp
        K is hashed_key
        
        returns a digest object"""
        assert isinstance(ts, int)
        assert isinstance(msg, Message)
        assert isinstance(hashed_key, str)

        sig = sha.new()
        h_msg = self.hash_msg(msg)

        sig.update(h_msg.digest())
        sig.update(str(ts))
        sig.update(hashed_key)
        return sig
    
    sign_msg = classmethod(sign_msg)



class Response(ThreadedMessage):
    ok_code = 200

    def ensure_complete(self):
        if not(self.has_key('Code') and self.has_key('Diag')):
            raise IncompleteMessageError, \
                  "doesn't have fields for a Response"
        super(Response, self).ensure_complete()

    def is_ok(self):
        return self.get_code() == self.ok_code

    def get_code(self):
        return int(self['Code'])

    def get_diag(self):
        return self['Diag']

    def head_tuple(self):
        return (self.get_code(), self.get_diag())


class Request(ThreadedMessage):
    """this is class that should be used to read in Requests of any type.
    subclasses are responsible for setting 'Op' if they are generating
    a message"""
    def get_op(self):
        return self['Op']

    def ensure_complete(self):
        if not self.has_key('Op'):
            raise IncompleteMessageError, \
                  "doesn't have fields for a Request"
        super(Request, self).ensure_complete()


class SuccessResponse(Response):
    def init_for_sending(self):
        super(SuccessResponse, self).init_for_sending()

        self.setdefault('Code', str(self.ok_code))
        self.setdefault('Diag', 'OK')


class PingRequest(Request):
    def __init__(self):
        super(PingRequest, self).__init__()
        self.setdefault('Op', 'ping')


class PingResponse(SuccessResponse):
    pass


class ReportRequest(Request):
    def __init__(self, digest, spec):
        assert isinstance(digest, str)
        assert isinstance(spec, PiecesDigestSpec)

        super(ReportRequest, self).__init__()

        self.setdefault('Op',        'report')
        self.setdefault('Op-Spec',   spec.netstring())
        self.setdefault('Op-Digest', str(digest))


class ReportResponse(SuccessResponse):
    pass


class CheckRequest(Request):
    def __init__(self, digest):
        assert isinstance(digest, str)
        
        super(CheckRequest, self).__init__()

        self.setdefault('Op',        'check')
        self.setdefault('Op-Digest', digest)


class CheckResponse(SuccessResponse):
    def __init__(self, count):
        assert isinstance(count, int)
        
        super(CheckResponse, self).__init__()
        self.setdefault('Count', str(count))

    def ensure_complete(self):
        if not self.has_key('Count'):
            raise IncompleteMessageError, \
                  "doesn't have fields for a CheckResponse"
        super(CheckResponse, self).ensure_complete()


class ErrorResponse(Response):
    def __init__(self, code, s):
        assert isinstance(code, int)
        assert isinstance(s, str)
        
        super(ErrorResponse, self).__init__()
        self.setdefault('Code', str(code))
        self.setdefault('Diag', s)


class ThreadId(int):
    # (0, 1024) is reserved
    full_range  = (0, 2**16)
    ok_range    = (1024, full_range[1])
    error_value = 0
    
    def __init__(self, i):
        super(ThreadId, self).__init__(i)
        if not (self.full_range[0] <= self < self.full_range[1]):
            raise ValueError, "value outside of range"

    def generate(self):
        return apply(self, (apply(random.randrange, self.ok_range),))
    generate = classmethod(generate)

    def in_ok_range(self):
        return (self >= self.ok_range[0] and self < self.ok_range[1])


class Address(tuple):
    def __init__(self, *varargs, **kwargs):
        super(Address, self).__init__(*varargs, **kwargs)
        self.validate()

    def validate(self):
        if len(self) != 2:
            raise ValueError, "invalid address: %s" % str(self)
    
    def __str__(self):
        return (self[0] + ':' + str(self[1]))

    def from_str(self, s):
        fields = s.split(':')

        fields[1] = int(fields[1])
        return apply(self, (fields,))

    from_str = classmethod(from_str)


class Config(ConfigParser.ConfigParser, object):
    
    def get_filename(self, section, option):
        return os.path.expanduser(self.get(section, option))

    def get_default_filename(self):
        homedir = get_homedir()
        
        if os.path.isfile(homedir):
            sys.stderr.write("In new versions of Pyzor, %s is a directory,\nand your current file %s\nneeds to be removed and re-generated with 'pyzor discover'.\n" \
                                 % (homedir, homedir))
            sys.exit(1)
        
        return os.path.join(homedir, 'config')
        
    get_default_filename = classmethod(get_default_filename)


def get_homedir():
    userhome = os.getenv('HOME')
    if userhome is None:
        sys.stderr.write('environment variable HOME is unset; please set it\n')
        sys.exit(1)

    return os.path.join(userhome, '.pyzor')
