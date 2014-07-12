"""This modules contains the various messages used in the pyzor client server
communication.
"""

import random
import email.message

import pyzor


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
        if 'Thread' not in self:
            self.set_thread(ThreadId.generate())
        assert 'Thread' in self
        self["PV"] = str(pyzor.proto_version)
        Message.init_for_sending(self)

    def ensure_complete(self):
        if 'PV' not in self or 'Thread' not in self:
            raise pyzor.IncompleteMessageError("Doesn't have fields for a "
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
        if 'Code' not in self or 'Diag' not in self:
            raise pyzor.IncompleteMessageError("doesn't have fields for a "
                                               "Response")
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
        if 'Op' not in self:
            raise pyzor.IncompleteMessageError("doesn't have fields for a "
                                               "Request")
        ThreadedMessage.ensure_complete(self)


class ClientSideRequest(Request):
    op = None

    def setup(self):
        Request.setup(self)
        self["Op"] = self.op


class SimpleDigestBasedRequest(ClientSideRequest):
    def __init__(self, digest=None):
        ClientSideRequest.__init__(self)
        self.digest_count = 0
        if digest:
            self.add_digest(digest)

    def add_digest(self, digest):
        self.add_header("Op-Digest", digest)
        self.digest_count += 1


class SimpleDigestSpecBasedRequest(SimpleDigestBasedRequest):
    def __init__(self, digest=None, spec=None):
        SimpleDigestBasedRequest.__init__(self, digest)
        if spec:
            flat_spec = [item for sublist in spec for item in sublist]
            self["Op-Spec"] = ",".join(str(part) for part in flat_spec)


class PingRequest(ClientSideRequest):
    op = "ping"


class PongRequest(SimpleDigestBasedRequest):
    op = "pong"


class CheckRequest(SimpleDigestBasedRequest):
    op = "check"


class InfoRequest(SimpleDigestBasedRequest):
    op = "info"


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
