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

anonymous_user = 'anonymous'

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
    op = None
    def setup(self):
        Request.setup(self)
        self["Op"] = self.op


class PingRequest(ClientSideRequest):
    op = "ping"


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
        flat_spec = [item for sublist in spec for item in sublist]
        self["Op-Spec"] = ",".join(str(part) for part in flat_spec)


class ReportRequest(SimpleDigestSpecBasedRequest):
    op = "report"


class WhitelistRequest(SimpleDigestSpecBasedRequest):
    op = "whitelist"


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


