"""networked spam-signature detection"""

__author__   = "Frank J. Tobin, ftobin@neverending.org"
__version__  = "0.6.0"
__revision__ = "$Id: __init__.py,v 1.43 2002-09-17 15:12:58 ftobin Exp $"

import os
import re
import sys
import time
import email
import random
import hashlib
import tempfile
import ConfigParser

try:
    import cStringIO as StringIO
except ImportError:
    import StringIO

proto_name     = 'pyzor'
proto_version  =  2.0

# We would like to use sha512, but that would mean that all the digests
# changed, so for now, we stick with sha1 (which is the same as the old
# sha module).
sha = hashlib.sha1

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


class BasicIterator(object):
    def __iter__(self):
        return self

    def next(self):
        raise NotImplementedError()


class Username(str):
    user_pattern = re.compile(r'^[-\.\w]+$')

    def __init__(self, s):
        self.validate()

    def validate(self):
        if not self.user_pattern.match(self):
            raise ValueError("%s is an invalid username" % self)


class Opname(str):
    op_pattern = re.compile(r'^[-\.\w]+$')

    def __init__(self, s):
        self.validate()

    def validate(self):
        if not self.op_pattern.match(self):
            raise ValueError("%s is an invalid username" % self)


class DataDigest(str):
    # hex output doubles digest size
    value_size = sha("").digest_size * 2

    def __init__(self, value):
        if len(value) != self.value_size:
            raise ValueError("invalid digest value size")


class DataDigestSpec(list):
    """a list of tuples, (perc_offset, length)"""

    def validate(self):
        for t in self:
            self.validate_tuple(t)

    @staticmethod
    def validate_tuple(t):
        (perc_offset, length) = t
        if not (0 <= perc_offset < 100):
            raise ValueError("offset percentage out of bounds")
        if not length > 0:
            raise ValueError("piece lengths must be positive")

    def netstring(self):
        # flattened, commified
        a = []
        for b in self:
            a.extend(b)
        return ",".join(str(s) for s in a)

    @classmethod
    def from_netstring(cls, s):
        new_spec = cls()
        expanded_list = s.split(',')
        if len(extended_list) % 2 != 0:
            raise ValueError("invalid list parity")
        for i in xrange(0, len(expanded_list), 2):
            perc_offset = int(expanded_list[i])
            length      = int(expanded_list[i+1])
            self.validate_tuple(perc_offset, length)
            new_spec.append((perc_offset, length))
        return new_spec


class Message(email.Message, object):
    # XXX fix.
    def __init__(self, fp=None):
        if fp is None:
            fp = StringIO.StringIO()
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
        raise NotImplementedError()

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
            raise IncompleteMessageError(
                "doesn't have fields for a ThreadedMessage")
        super(ThreadedMessage, self).ensure_complete()

    def get_protocol_version(self):
        return float(self['PV'])

    def get_thread(self):
        return ThreadId(self['Thread'])

    def set_thread(self, i):
        typecheck(i, ThreadId)
        self['Thread'] = str(i)


class MacEnvelope(Message):
    ts_diff_max = 300

    def ensure_complete(self):
        if not (self.has_key('User')
                and self.has_key('Time')
                and self.has_key('Sig')):
             raise IncompleteMessageError(
                "doesn't have fields for a MacEnvelope")
        super(MacEnvelope, self).ensure_complete()

    def get_submsg(self, factory=ThreadedMessage):
        self.rewindbody()
        return factory(self.fp)

    def verify_sig(self, user_key):
        typecheck(user_key, long)

        user     = Username(self['User'])
        ts       = int(self['Time'])
        said_sig = self['Sig']
        hashed_user_key = self.hash_key(user_key, user)

        if abs(time.time() - ts) > self.ts_diff_max:
            raise SignatureError("timestamp not within allowed range")

        msg = self.get_submsg()
        calc_sig = self.sign_msg(hashed_user_key, ts, msg)
        if not (calc_sig == said_sig):
            raise SignatureError("invalid signature")

    @classmethod
    def wrap(cls, user, key, msg):
        """This should be used to create a MacEnvelope"""

        typecheck(user, str)
        typecheck(msg, Message)
        typecheck(key, long)

        env = cls()
        ts = int(time.time())
        env['User'] = user
        env['Time'] = str(ts)
        env['Sig'] = cls.sign_msg(cls.hash_key(key, user), ts, msg)
        env.fp.write(str(msg))
        return env

    @staticmethod
    def hash_msg(msg):
        """returns a digest object"""
        typecheck(msg, Message)
        return sha(str(msg))

    @staticmethod
    def hash_key(key, user):
        """returns lower(H(U + ':' + lower(hex(K))))"""
        typecheck(key, long)
        typecheck(user, Username)
        return sha("%s:%x" % (Username, key)).hexdigest().lower()

    @classmethod
    def sign_msg(cls, hashed_key, ts, msg):
        """ts is timestamp for message (epoch seconds)

        S = H(H(M) + ':' T + ':' + K)
        M is message
        T is decimal epoch timestamp
        K is hashed_key

        returns a digest object"""

        typecheck(ts, int)
        typecheck(msg, Message)
        typecheck(hashed_key, str)
        h_msg = cls.hash_msg(msg)
        return sha("%s:%d:%s" % (h_msg.digest(), ts,
                                 hashed_key)).hexdigest().lower()


class Response(ThreadedMessage):
    ok_code = 200

    def ensure_complete(self):
        if not(self.has_key('Code') and self.has_key('Diag')):
            raise IncompleteMessageError(
                "doesn't have fields for a Response")
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
    """This is the class that should be used to read in Requests of any type.
    Subclasses are responsible for setting 'Op' if they are generating a
    message,"""

    def get_op(self):
        return self['Op']

    def ensure_complete(self):
        if not self.has_key('Op'):
            raise IncompleteMessageError(
                "doesn't have fields for a Request")
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
        typecheck(spec, DataDigestSpec)
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
            raise ValueError("value outside of range")

    @classmethod
    def generate(cls):
        return cls(random.randrange(cls.ok_range))

    def in_ok_range(self):
        return (self >= self.ok_range[0] and self < self.ok_range[1])


class Address(tuple):
    def __init__(self, *varargs, **kwargs):
        self.validate()

    def validate(self):
        typecheck(self[0], str)
        typecheck(self[1], int)
        if len(self) != 2:
            raise ValueError("invalid address: %s" % self)

    def __str__(self):
        return (self[0] + ':' + str(self[1]))

    @classmethod
    def from_str(cls, s):
        fields = s.split(':')
        fields[1] = int(fields[1])
        return cls(fields)


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
        raise TypeError()

def modglobal_apply(globs, repl, obj, varargs=(), kwargs=None):
    """temporarily modify globals during a call.
    globs is the globals to modify (e.g., the return from globals())
    repl is a dictionary of name: value replacements for the global
    dict."""
    if kwargs is None:
        kwargs = {}
    saved = {}
    for (k, v) in repl.items():
        saved[k] = globs[k]
        globs[k] = v
    try:
        r = obj(*varargs, **kwargs)
    finally:
        globs.update(saved)
    return r

anonymous_user = Username('anonymous')
