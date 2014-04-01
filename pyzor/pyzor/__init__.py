"""Networked spam-signature detection."""

__author__ = "Frank J. Tobin, ftobin@neverending.org"
__credits__ = "Tony Meyer, Dreas von Donselaar, all the Pyzor contributors."
__version__ = "0.6.1"

import os
import time
import email
import random
import hashlib
import ConfigParser
import email.message

proto_name = 'pyzor'
proto_version = 2.1

# We would like to use sha512, but that would mean that all the digests
# changed, so for now, we stick with sha1 (which is the same as the old
# sha module).
sha = hashlib.sha1


class CommError(Exception):
    """Something in general went wrong with the transaction."""
    pass


class ProtocolError(CommError):
    """Something is wrong with talking the protocol."""
    pass


class TimeoutError(CommError):
    """The connection timed out."""
    pass


class IncompleteMessageError(ProtocolError):
    """A complete requested was not received."""
    pass


class UnsupportedVersionError(ProtocolError):
    """Client is using an unsupported protocol version."""
    pass


class SignatureError(CommError):
    """Unknown user, signature on msg invalid, or not within allowed time
    range."""
    pass


class AuthorizationError(CommError):
    """The signature was valid, but the user is not permitted to do the
    requested action."""
    pass


class Message(email.message.Message):
    def __init__(self):
        email.message.Message.__init__(self)
        self.setup()

    def setup(self):
        pass

    def init_for_sending(self):
        self.ensure_complete()

    def __str__(self):
        # The parent class adds the unix From header.
        return self.as_string()

    def ensure_complete(self):
        pass


class ThreadedMessage(Message):
    def init_for_sending(self):
        if not self.has_key('Thread'):
            self.set_thread(ThreadId.generate())
        assert self.has_key('Thread')
        self["PV"] = str(proto_version)
        Message.init_for_sending(self)

    def ensure_complete(self):
        if not (self.has_key('PV') and self.has_key('Thread')):
            raise IncompleteMessageError("Doesn't have fields for a "
                                         "ThreadedMessage.")
        Message.ensure_complete(self)

    def get_protocol_version(self):
        return float(self['PV'])

    def get_thread(self):
        return ThreadId(self['Thread'])

    def set_thread(self, i):
        self['Thread'] = str(i)


class MacEnvelope(Message):
    ts_diff_max = 300

    def ensure_complete(self):
        if not (self.has_key('User') and self.has_key('Time')
                and self.has_key('Sig')):
            raise IncompleteMessageError("Doesn't have fields for a "
                                         "MacEnvelope.")
        Message.ensure_complete(self)

    def get_submsg(self, factory=ThreadedMessage):
        # XXX Fix.
        self.rewindbody()
        return factory(self.fp)

    def verify_sig(self, user_key):

        user = self['User']
        ts = int(self['Time'])
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

        env = cls()
        ts = int(time.time())
        env['User'] = user
        env['Time'] = str(ts)
        env['Sig'] = cls.sign_msg(cls.hash_key(key, user), ts, msg)
        env.set_payload(str(msg))
        return env

    @staticmethod
    def hash_msg(msg):
        """returns a digest object"""
        return sha(str(msg).encode("utf8"))

    @staticmethod
    def hash_key(key, user):
        """returns lower(H(U + ':' + lower(hex(K))))"""
        key = ("%s:%x" % (user, key)).encode("utf8")
        return sha(key).hexdigest().lower()

    @classmethod
    def sign_msg(cls, hashed_key, ts, msg):
        """ts is timestamp for message (epoch seconds)

        S = H(H(M) + ':' T + ':' + K)
        M is message
        T is decimal epoch timestamp
        K is hashed_key

        returns a digest object"""

        digest = sha()
        digest.update(cls.hash_msg(msg).digest())
        digest.update((":%d:%s" % (ts, hashed_key)).encode("utf8"))
        return digest.hexdigest().lower()


class Response(ThreadedMessage):
    ok_code = 200

    def ensure_complete(self):
        if not (self.has_key('Code') and self.has_key('Diag')):
            raise IncompleteMessageError(
                "doesn't have fields for a Response")
        ThreadedMessage.ensure_complete(self)

    def is_ok(self):
        return self.get_code() == self.ok_code

    def get_code(self):
        return int(self['Code'])

    def get_diag(self):
        return self['Diag']

    def head_tuple(self):
        return self.get_code(), self.get_diag()


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
        ThreadedMessage.ensure_complete(self)


class ClientSideRequest(Request):
    def setup(self):
        Request.setup(self)
        self["Op"] = self.op


class PingRequest(ClientSideRequest):
    op = "ping"


class ShutdownRequest(ClientSideRequest):
    op = "shutdown"


class SimpleDigestBasedRequest(ClientSideRequest):
    def __init__(self, digest):
        ClientSideRequest.__init__(self)
        self["Op-Digest"] = digest


class PongRequest(SimpleDigestBasedRequest):
    op = "pong"


class CheckRequest(SimpleDigestBasedRequest):
    op = "check"


class InfoRequest(SimpleDigestBasedRequest):
    op = "info"


class SimpleDigestSpecBasedRequest(SimpleDigestBasedRequest):
    def __init__(self, digest, spec):
        SimpleDigestBasedRequest.__init__(self, digest)
        flat_spec = []
        [flat_spec.extend(part) for part in spec]
        self["Op-Spec"] = ",".join(str(part) for part in flat_spec)


class ReportRequest(SimpleDigestSpecBasedRequest):
    op = "report"


class WhitelistRequest(SimpleDigestSpecBasedRequest):
    op = "whitelist"


class ErrorResponse(Response):
    def __init__(self, code, s):
        Response.__init__(self)
        self["Code"] = str(code)
        self["Diag"] = s


class ThreadId(int):
    # (0, 1024) is reserved
    full_range = (0, 2 ** 16)
    ok_range = (1024, full_range[1])
    error_value = 0

    def __new__(cls, i):
        self = int.__new__(cls, i)
        if not (cls.full_range[0] <= self < cls.full_range[1]):
            raise ValueError("value outside of range")
        return self

    @classmethod
    def generate(cls):
        return cls(random.randrange(*cls.ok_range))

    def in_ok_range(self):
        return self.ok_range[0] <= self < self.ok_range[1]


class Config(ConfigParser.ConfigParser):
    def __init__(self, homedir):
        assert isinstance(homedir, str)
        self.homedir = homedir
        ConfigParser.ConfigParser.__init__(self)

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


anonymous_user = 'anonymous'
