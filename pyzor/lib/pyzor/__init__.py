"""networked spam-signature detection"""

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

__author__   = "Frank J. Tobin, ftobin@neverending.org"
__version__  = "0.3.1"
__revision__ = "$Id: __init__.py,v 1.32 2002-08-19 01:56:39 ftobin Exp $"

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


class CommError(Exception):
    """Something in general went wrong with the transaction"""
    pass



class ProtocolError(CommError):
    """Something is wrong with talking the protocol"""
    pass



class TimeoutError(CommError):
    pass



class IncompleteMessageError(ProtocolError):
    pass



class UnsupportedVersionError(ProtocolError):
    pass



class SignatureError(CommError):
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
        self.validate()

    def validate(self):
        if not self.user_pattern.match(self):
            raise ValueError, "%s is an invalid username" % self



class Opname(str):
    op_pattern = re.compile(r'^[-\.\w]+$')
    
    def __init__(self, s):
        self.validate()

    def validate(self):
        if not self.op_pattern.match(self):
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
    min_line_length = 8

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

    def __init__(self, value):
        if len(value) != self.value_size:
            raise ValueError, "invalid digest value size"

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
        repl = self.unwanted_txt_repl
        s2 = s
        s2 = self.email_ptrn.sub(repl, s2)
        s2 = self.url_ptrn.sub(repl, s2)
        s2 = self.longstr_ptrn.sub(repl, s2)
        s2 = self.html_tag_ptrn.sub(repl, s2)
        # make sure we do the whitespace last because some of
        # the previous patterns rely on whitespace
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

        while True:
            buf = fp.read(self.bufsize)
            line_offsets.extend(map(lambda x: cur_offset + x,
                                    self.get_line_offsets(buf)))
            if not buf:
                break
            cur_offset += len(buf)
            
            if newfp:
                newfp.write(buf)

        if newfp:
            fp = newfp

        # did we get an empty file?
        if len(line_offsets) == 0:
            return None
            
        digest = sha.new()
        
        for (perc_offset, length) in spec:
            assert 0 <= perc_offset < 100

            offset = line_offsets[int(perc_offset * len(line_offsets)
                                      / 100.0)]
            fp.seek(offset)

            i = 0
            while i < length:
                line = fp.readline()
                if not line:
                    break
                norm_line = self.normalize(line)
                if len(norm_line) < self.min_line_length:
                    continue
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
        self.setup()


    def setup(self):
        """called after __init__, designed to be extended"""
        pass


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
        typecheck(i, ThreadId)
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
        typecheck(user_key, long)
        
        user     = Username(self['User'])
        ts       = int(self['Time'])
        said_sig = self['Sig']
        hashed_user_key = self.hash_key(user_key, user)
        
        if abs(time.time() - ts) > self.ts_diff_max:
            raise SignatureError, "timestamp not within allowed range"

        msg = self.get_submsg()

        calc_sig = self.sign_msg(hashed_user_key, ts, msg)

        if not (calc_sig == said_sig):
            raise SignatureError, "invalid signature"

    def wrap(self, user, key, msg):
        """This should be used to create a MacEnvelope"""
        
        typecheck(user, str)
        typecheck(msg, Message)
        typecheck(key, long)

        env = apply(self)
        ts = int(time.time())

        env['User'] = user
        env['Time'] = str(ts)
        env['Sig'] = self.sign_msg(self.hash_key(key, user),
                                   ts, msg)

        env.fp.write(str(msg))

        return env

    wrap = classmethod(wrap)


    def hash_msg(msg):
        """returns a digest object"""
        typecheck(msg, Message)

        return sha.new(str(msg))

    hash_msg = staticmethod(hash_msg)


    def hash_key(key, user):
        """returns lower(H(U + ':' + lower(hex(K))))"""
        typecheck(key, long)
        typecheck(user, Username)
        
        return sha.new("%s:%x" % (Username, key)).hexdigest().lower()
    
    hash_key = staticmethod(hash_key)


    def sign_msg(self, hashed_key, ts, msg):
        """ts is timestamp for message (epoch seconds)

        S = H(H(M) + ':' T + ':' + K)
        M is message
        T is decimal epoch timestamp
        K is hashed_key
        
        returns a digest object"""
        
        typecheck(ts, int)
        typecheck(msg, Message)
        typecheck(hashed_key, str)

        h_msg = self.hash_msg(msg)

        return sha.new("%s:%d:%s" % (h_msg.digest(), ts, hashed_key)).hexdigest().lower()
    
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



class ClientSideRequest(Request):
    def setup(self):
        super(Request, self).setup()
        self.setdefault('Op', self.op)
        


class PingRequest(ClientSideRequest):
    op = Opname('ping')


class ShutdownRequest(ClientSideRequest):
    op = Opname('shutdown')


class SimpleDigestBasedRequest(ClientSideRequest):
    def __init__(self, digest):
        typecheck(digest, str)
        super(SimpleDigestBasedRequest, self).__init__()
        self.setdefault('Op-Digest', digest)


class CheckRequest(SimpleDigestBasedRequest):
    op = Opname('check')


class InfoRequest(SimpleDigestBasedRequest):
    op = Opname('info')


class SimpleDigestSpecBasedRequest(SimpleDigestBasedRequest):
    def __init__(self, digest, spec):
        typecheck(digest, str)
        typecheck(spec, PiecesDigestSpec)

        super(SimpleDigestSpecBasedRequest, self).__init__(digest)
        self.setdefault('Op-Spec',   spec.netstring())


class ReportRequest(SimpleDigestSpecBasedRequest):
    op = Opname('report')


class WhitelistRequest(SimpleDigestSpecBasedRequest):
    op = Opname('whitelist')


class ErrorResponse(Response):
    def __init__(self, code, s):
        typecheck(code, int)
        typecheck(s, str)
        
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
        self.validate()

    def validate(self):
        typecheck(self[0], str)
        typecheck(self[1], int)
        if len(self) != 2:
            raise ValueError, "invalid address: %s" % str(self)
    
    def __str__(self):
        return (self[0] + ':' + str(self[1]))

    def from_str(self, s):
        fields = s.split(':')

        fields[1] = int(fields[1])
        return self(fields)

    from_str = classmethod(from_str)



class Config(ConfigParser.ConfigParser, object):

    def __init__(self, homedir):
        assert isinstance(homedir, str)
        self.homedir = homedir
        super(Config, self).__init__()
    
    def get_filename(self, section, option):
        fn = os.path.expanduser(self.get(section, option))
        if not os.path.isabs(fn):
            fn = os.path.join(self.homedir, fn)
        return fn


def get_homedir(specified):
    homedir = os.path.join('/etc', 'pyzor')
    
    if specified is not None:
        homedir = specified
    else:
        userhome = os.getenv('HOME')
        if userhome is not None:
            homedir = os.path.join(userhome, '.pyzor')
    
    return homedir


def typecheck(inst, type_):
    if not isinstance(inst, type_):
        raise TypeError

anonymous_user = Username('anonymous')
