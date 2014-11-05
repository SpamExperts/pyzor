"""Networked spam-signature detection client.

>>> import pyzor
>>> import pyzor.client
>>> import pyzor.digest
>>> import pyzor.config

To load the accounts file:

>>> accounts = pyzor.config.load_accounts(filename)

To create a client (to then issue commands):

>>> client = pyzor.client.Client(accounts)

To create a client, using the anonymous user:

>>> client = pyzor.client.Client()

To get a digest (of an email.message.Message object, or similar):

>>> digest = pyzor.digest.get_digest(msg)

To query a server (where address is a (host, port) pair):

>>> client.ping(address)
>>> client.info(digest, address)
>>> client.report(digest, address)
>>> client.whitelist(digest, address)
>>> client.check(digest, address)

To query the default server (public.pyzor.org):

>>> client.ping()
>>> client.info(digest)
>>> client.report(digest)
>>> client.whitelist(digest)
>>> client.check(digest)

Response will contain, depending on the type of request, some
of the following keys (e.g. client.ping()['Code']):

All responses will have:
- 'Diag' 'OK' or error message
- 'Code' '200' if OK
- 'PV' Protocol Version
- 'Thread'

`info` and `check` responses will also contain:
- '[WL-]Count' Whitelist/Blacklist count

`info` responses will also have:
- '[WL-]Entered' timestamp when message was first whitelisted/blacklisted
- '[WL-]Updated' timestamp when message was last whitelisted/blacklisted
"""

import time
import email
import socket
import logging
import functools
import collections

import pyzor.digest
import pyzor.account
import pyzor.message

import pyzor.hacks.py26

pyzor.hacks.py26.hack_email()


class Client(object):
    timeout = 5
    max_packet_size = 8192

    def __init__(self, accounts=None, timeout=None, spec=None):
        if accounts is None:
            accounts = {}
        self.accounts = dict(((host, int(port)), account)
                             for (host, port), account in accounts.iteritems())
        if spec is None:
            spec = pyzor.digest.digest_spec
        self.spec = spec
        if timeout is not None:
            self.timeout = timeout
        self.log = logging.getLogger("pyzor")

    def ping(self, address=("public.pyzor.org", 24441)):
        msg = pyzor.message.PingRequest()
        sock = self.send(msg, address)
        return self.read_response(sock, msg.get_thread())

    def pong(self, digest, address=("public.pyzor.org", 24441)):
        msg = pyzor.message.PongRequest(digest)
        sock = self.send(msg, address)
        return self.read_response(sock, msg.get_thread())

    def info(self, digest, address=("public.pyzor.org", 24441)):
        msg = pyzor.message.InfoRequest(digest)
        sock = self.send(msg, address)
        return self.read_response(sock, msg.get_thread())

    def report(self, digest, address=("public.pyzor.org", 24441)):
        msg = pyzor.message.ReportRequest(digest, self.spec)
        sock = self.send(msg, address)
        return self.read_response(sock, msg.get_thread())

    def whitelist(self, digest, address=("public.pyzor.org", 24441)):
        msg = pyzor.message.WhitelistRequest(digest, self.spec)
        sock = self.send(msg, address)
        return self.read_response(sock, msg.get_thread())

    def check(self, digest, address=("public.pyzor.org", 24441)):
        msg = pyzor.message.CheckRequest(digest)
        sock = self.send(msg, address)
        return self.read_response(sock, msg.get_thread())

    def _mock_check(self, digests, address=None):
        msg = (b"Code: %s\nDiag: OK\nPV: %s\nThread: 1024\nCount: 0\n"
               b"WL-Count: 0" % (pyzor.message.Response.ok_code,
                                 pyzor.proto_version))
        return email.message_from_bytes(msg, _class=pyzor.message.Response)

    def send(self, msg, address=("public.pyzor.org", 24441)):
        address = (address[0], int(address[1]))
        msg.init_for_sending()
        try:
            account = self.accounts[address]
        except KeyError:
            account = pyzor.account.AnonymousAccount
        timestamp = int(time.time())
        msg["User"] = account.username
        msg["Time"] = str(timestamp)
        msg["Sig"] = pyzor.account.sign_msg(pyzor.account.hash_key(
            account.key, account.username), timestamp, msg)
        self.log.debug("sending: %r", msg.as_string())
        return self._send(msg, address)

    @staticmethod
    def _send(msg, addr):
        sock = None
        for res in socket.getaddrinfo(addr[0], addr[1], 0, socket.SOCK_DGRAM,
                                      socket.IPPROTO_UDP):
            af, socktype, proto, _, sa = res
            try:
                sock = socket.socket(af, socktype, proto)
            except socket.error:
                sock = None
                continue
            try:
                sock.sendto(msg.as_string().encode("utf8"), 0, sa)
            except socket.timeout:
                sock.close()
                raise pyzor.TimeoutError("Sending to %s time-outed" % sa)
            except socket.error:
                sock.close()
                sock = None
                continue
            break
        if sock is None:
            raise pyzor.CommError("Unable to send to %s:%s" % addr)
        return sock

    def read_response(self, sock, expected_id):
        sock.settimeout(self.timeout)
        try:
            packet, address = sock.recvfrom(self.max_packet_size)
        except socket.timeout as ex:
            sock.close()
            raise pyzor.TimeoutError("Reading response timed-out.")
        except socket.error as ex:
            sock.close()
            raise pyzor.CommError("Socket error while reading response: %s" %
                                  ex)

        self.log.debug("received: %r/%r", packet, address)
        msg = email.message_from_bytes(packet, _class=pyzor.message.Response)
        msg.ensure_complete()
        try:
            thread_id = msg.get_thread()
            if thread_id != expected_id:
                if thread_id.in_ok_range():
                    raise pyzor.ProtocolError(
                        "received unexpected thread id %d (expected %d)" %
                        (thread_id, expected_id))
                self.log.warn("received error thread id %d (expected %d)",
                              thread_id, expected_id)
        except KeyError:
            self.log.warn("no thread id received")
        return msg


class BatchClient(Client):
    """Like the normal Client but with support for batching reports."""

    def __init__(self, accounts=None, timeout=None, spec=None, batch_size=10):
        Client.__init__(self, accounts=accounts, timeout=timeout, spec=spec)
        self.batch_size = batch_size
        self.r_requests = {}
        self.w_requests = {}
        self.flush()

    def report(self, digest, address=("public.pyzor.org", 24441)):
        self._add_digest(digest, address, self.r_requests)

    def whitelist(self, digest, address=("public.pyzor.org", 24441)):
        self._add_digest(digest, address, self.w_requests)

    def _add_digest(self, digest, address, requests):
        address = (address[0], int(address[1]))
        msg = requests[address]

        msg.add_digest(digest)
        if msg.digest_count >= self.batch_size:
            try:
                return self.send(msg, address)
            finally:
                del requests[address]

    def flush(self):
        """Deleting any saved digest reports."""
        self.r_requests = collections.defaultdict(
            functools.partial(pyzor.message.ReportRequest, spec=self.spec))
        self.w_requests = collections.defaultdict(
            functools.partial(pyzor.message.WhitelistRequest, spec=self.spec))

    def force(self):
        """Force send any remaining reports."""
        for address, msg in self.r_requests.iteritems():
            try:
                self.send(msg, address)
            except:
                continue
        for address, msg in self.w_requests.iteritems():
            try:
                self.send(msg, address)
            except:
                continue

    def __del__(self):
        self.force()


class ClientRunner(object):
    def __init__(self, routine):
        self.log = logging.getLogger("pyzor")
        self.routine = routine
        self.all_ok = True
        self.results = []

    def run(self, server, args, kwargs=None):
        if kwargs is None:
            kwargs = {}
        message = "%s:%s\t" % server
        response = None
        try:
            response = self.routine(*args, **kwargs)
            self.handle_response(response, message)
        except (pyzor.CommError, KeyError, ValueError) as e:
            self.results.append("%s%s\n" % (message, (e.code, str(e))))
            self.log.error("%s\t%s: %s", server, e.__class__.__name__, e)
            self.all_ok = False

    def handle_response(self, response, message):
        """mesaage is a string we've built up so far"""
        if not response.is_ok():
            self.all_ok = False
        self.results.append("%s%s\n" % (message, response.head_tuple()))


class CheckClientRunner(ClientRunner):
    def __init__(self, routine, r_count=0, wl_count=0):
        ClientRunner.__init__(self, routine)
        self.found_hit = False
        self.whitelisted = False
        self.hit_count = 0
        self.whitelist_count = 0
        self.r_count_found = r_count
        self.wl_count_clears = wl_count

    def handle_response(self, response, message):
        message += "%s\t" % str(response.head_tuple())
        if response.is_ok():
            self.hit_count = int(response['Count'])
            self.whitelist_count = int(response['WL-Count'])
            if self.whitelist_count > self.wl_count_clears:
                self.whitelisted = True
            elif self.hit_count > self.r_count_found:
                self.found_hit = True
            message += "%d\t%d" % (self.hit_count, self.whitelist_count)
        else:
            self.all_ok = False
        self.results.append(message + "\n")


class InfoClientRunner(ClientRunner):
    def handle_response(self, response, message):
        message += "%s\n" % str(response.head_tuple())

        if response.is_ok():
            for key in ('Count', 'Entered', 'Updated', 'WL-Count',
                        'WL-Entered', 'WL-Updated'):
                if key in response:
                    val = int(response[key])
                    if 'Count' in key:
                        stringed = str(val)
                    elif val == -1:
                        stringed = 'Never'
                    else:
                        stringed = time.ctime(val)
                    message += ("\t%s: %s\n" % (key, stringed))
        else:
            self.all_ok = False
        self.results.append(message + "\n")
