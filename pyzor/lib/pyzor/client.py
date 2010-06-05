"""Networked spam-signature detection client.

To load the accounts file:

>>> accounts = pyzor.accounts.load_accounts(filename)

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
"""

import re
import os
import getopt
import random
import socket
import signal
import urllib2
import hashlib
import logging
import tempfile
import mimetools
import multifile

try:
    import cStringIO as StringIO
except ImportError:
    import StringIO

# XXX This is very messy.  Everything is in two namespaces (local and pyzor).
import pyzor
import pyzor.digest
from pyzor import *

sha = pyzor.sha

class Client(object):
    timeout = 5
    max_packet_size = 8192

    def __init__(self, accounts=None, timeout=None):
        if accounts:
            self.accounts = accounts
        else:
            self.accounts = {}
        if timeout is not None:
            self.timeout = timeout
        self.log = logging.getLogger("pyzor")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def ping(self, address=("public.pyzor.org", 24441)):
        msg = PingRequest()
        self.send(msg, address)
        return self.read_response(msg.get_thread())

    def info(self, digest, address=("public.pyzor.org", 24441)):
        msg = InfoRequest(digest)
        self.send(msg, address)
        return self.read_response(msg.get_thread())

    def report(self, digest, address=("public.pyzor.org", 24441),
               spec=pyzor.digest.digest_spec):
        msg = ReportRequest(digest, spec)
        self.send(msg, address)
        return self.read_response(msg.get_thread())

    def whitelist(self, digest, address=("public.pyzor.org", 24441),
                  spec=pyzor.digest.digest_spec):
        msg = WhitelistRequest(digest, spec)
        self.send(msg, address)
        return self.read_response(msg.get_thread())

    def check(self, digest, address=("public.pyzor.org", 24441)):
        msg = CheckRequest(digest)
        self.send(msg, address)
        return self.read_response(msg.get_thread())

    def send(self, msg, address=("public.pyzor.org", 24441)):
        msg.init_for_sending()
        try:
            account = self.accounts[address]
        except KeyError:
            account = pyzor.account.AnonymousAccount
        mac_msg_str = str(MacEnvelope.wrap(account.username,
                                           account.key, msg))
        self.log.debug("sending: %r" % mac_msg_str)
        self.socket.sendto(mac_msg_str, 0, address)

    def time_call(self, call, args=(), kwargs=None):
        if kwargs is None:
            kwargs = {}
        signal.signal(signal.SIGALRM, handle_timeout)
        signal.alarm(self.timeout)
        try:
            return call(*args, **kwargs)
        finally:
            signal.alarm(0)

    def read_response(self, expected_id):
        packet, address = self.time_call(self.socket.recvfrom,
                                         (self.max_packet_size,))
        self.log.debug("received: %r" % packet)
        msg = Response(StringIO.StringIO(packet))
        msg.ensure_complete()
        try:
            thread_id = msg.get_thread()
            if thread_id != expected_id:
                if thread_id.in_ok_range():
                    raise ProtocolError(
                        "received unexpected thread id %d (expected %d)" %
                        (thread_id, expected_id))
                self.log.warn("received error thread id %d (expected %d)" %
                              (thread_id, expected_id))
        except KeyError:
            self.log.warn("no thread id received")
        return msg


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
            response = self.routine(*varargs, **kwargs)
            self.handle_response(response, message)
        except (CommError, KeyError, ValueError), e:
            # XXX This should write to the log.
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
    # the number of wl-count it takes for the normal
    # count to be overriden
    wl_count_clears = 1

    def setup(self):
        self.found_hit = False
        self.whitelisted = False
        self.hit_count = 0
        self.whitelist_count = 0
        super(CheckClientRunner, self).setup()

    def handle_response(self, response, message):
        message += "%s\t" % str(response.head_tuple())
        if response.is_ok():
            self.hit_count = int(response['Count'])
            self.whitelist_count = int(response['WL-Count'])
            if self.whitelist_count > wl_count_clears:
                count = 0
                self.whitelisted = True
            else:
                if self.hit_count > 0:
                    self.found_hit = True
            message += "%d\t%d" % (count, wl_count)
            sys.stdout.write(message + '\n')
        else:
            # XXX This should write to the log.
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
                        if f == 'WL-Entered':
                            message += ("\tWhiteList Count: %d\n"
                                        % int(response['WL-Count']))

                        message += ("\t%s: %s\n" % (f, stringed))

            sys.stdout.write(message)
        else:
            # XXX This should write to the log.
            sys.stderr.write(message)


def handle_timeout(signum, frame):
    raise TimeoutError()
