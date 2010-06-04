"""networked spam-signature detection server"""

from __future__ import division

import os
import re
import sys
import time
import logging
import datetime
import cStringIO
import traceback
import threading
import SocketServer

import pyzor
from pyzor import *

import pyzor.server_engines

__author__   = pyzor.__author__
__version__  = pyzor.__version__
__revision__ = "$Id: server.py,v 1.29 2002-10-09 00:45:45 ftobin Exp $"


class AuthorizationError(pyzor.CommError):
    """signature was valid, but not permitted to do the requested action"""
    pass


class ACL(object):
    __slots__ = ['entries']
    default_allow = False

    def __init__(self):
        self.entries = []

    def add_entry(self, entry):
        typecheck(entry, ACLEntry)
        self.entries.append(entry)

    def allows(self, user, op):
        typecheck(op,   Opname)
        for entry in self.entries:
            if entry.allows(user, op):
                return True
            if entry.denies(user, op):
                return False
        return self.default_allow


class ACLEntry(tuple):
    all_keyword = 'all'

    def __init__(self, v):
        (user, op, allow) = v
        typecheck(op,    Opname)
        assert bool(allow) == allow

    @property
    def user(self):
        return self[0]

    @property
    def op(self):
        return self[1]

    @property
    def allow(self):
        return self[2]

    def allows(self, user, op):
        return self._says(user, op, True)

    def denies(self, user, op):
        return self._says(user, op, False)

    def _says(self, user, op, allow):
        """If allow is True, we return true if and only if we allow user to do op.
        If allow is False, we return true if and only if we deny user to do op
        """
        typecheck(op,    Opname)
        assert bool(allow) == allow

        return (self.allow == allow
                and (self.user == user
                     or self.user.lower() == self.all_keyword)
                and (self.op == op
                     or self.op.lower() == self.all_keyword))


class AccessFile(object):
    # I started doing an iterator protocol for this, but it just
    # got too complicated keeping track of everything on the line.
    __slots__ = ['file', 'log', 'lineno']
    allow_keyword = 'allow'
    deny_keyword = 'deny'

    def __init__(self, f):
        self.log = logging.getLogger("pyzord")
        self.file = f
        self.lineno = 0

    def feed_into(self, acl):
        typecheck(acl, ACL)

        for orig_line in self.file:
            self.lineno += 1

            line = orig_line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split(':')

            if len(parts) != 3:
                self.log.warn("access file: invalid number of parts in line %d" %
                              self.lineno)
                continue

            (ops_str, users_str, allow_str) = parts

            ops = []
            for op_str in ops_str.split():
                try:
                    op = Opname(op_str)
                except ValueError, e:
                    self.log.warn("access file: invalid opname %s line %d: %s" %
                                  (repr(op_str), self.lineno, e))
                else:
                    ops.append(op)

            users = []
            for u in users_str.split():
                if re.match(pyzor.VALID_USERNAME_RE, u):
                    users.append(u)
                else:
                    self.log.warn("access file: invalid username %s line %d: %s" %
                                  (repr(u), self.lineno, e))

            allow_str = allow_str.strip()
            if allow_str.lower() == self.allow_keyword:
                allow = True
            elif allow_str.lower() == self.deny_keyword:
                allow = False
            else:
                self.log.warn("access file: invalid allow/deny keyword %s line %d" %
                              (repr(allow_str), self.lineno))
                continue

            for op in ops:
                for user in users:
                    acl.add_entry(ACLEntry((user, op, allow)))


class Passwd(dict):
    def __setitem__(self, k, v):
        typecheck(v, long)
        super(Passwd, self).__setitem__(k, v)


class PasswdFile(object):
    """Iteration gives (Username, long) objects

    Format of file is:
    user : key
    """
    __slots__ = ['file', 'log', 'lineno']

    def __init__(self, f):
        self.file = f
        self.log = logging.getLogger("pyzord")
        self.lineno = 0

    def __iter__(self):
        return self

    def next(self):
        while True:
            orig_line = self.file.readline()
            self.lineno += 1

            if not orig_line:
                raise StopIteration

            line = orig_line.strip()
            if not line or line.startswith('#'):
                continue
            fields = line.split(':')
            fields = map(lambda x: x.strip(), fields)

            if len(fields) != 2:
                self.log.warn("passwd line %d is invalid (wrong number of parts)" %
                              self.lineno)
                continue

            try:
                return (fields[0], long(fields[1], 16))
            except ValueError, e:
                self.log.warn("invalid passwd entry line %d: %s" %
                              (self.lineno, e))


class Log(object):
    __slots__ = ['fp']

    def __init__(self, fp=None):
        self.fp = fp

    def log(self, address, user=None, command=None, arg=None, code=None):
        # we don't use defaults because we want to be able
        # to pass in None
        if user    is None: user = ''
        if command is None: command = ''
        if arg     is None: arg = ''
        if code    is None: code = -1

        # We duplicate the time field merely so that
        # humans can peruse through the entries without processing
        ts = int(time.time())
        if self.fp is not None:
            self.fp.write("%s\n" %
                          ','.join((("%d" % ts),
                                    time.ctime(ts),
                                    user,
                                    address[0],
                                    command,
                                    repr(arg),
                                    ("%d" % code)
                                    )))
            self.fp.flush()


class Server(SocketServer.UDPServer):
    max_packet_size = 8192
    time_diff_allowance = 180

    def __init__(self, address, database):
        self.log = logging.getLogger("pyzord")
        self.usage_log = logging.getLogger("pyzord-usage")
        RequestHandler.log = self.log
        RequestHandler.usage_log = self.usage_log
        RequestHandler.db = database
        self.log.debug('listening on %s' % repr(address))
        SocketServer.UDPServer.__init__(self, address, RequestHandler)

    def serve_forever(self):
        self.pid = os.getpid()
        SocketServer.UDPServer.serve_forever(self)


class ThreadingServer(Server, SocketServer.ThreadingUDPServer):
    pass


class RequestHandler(SocketServer.DatagramRequestHandler):
    def setup(self):
        SocketServer.DatagramRequestHandler.setup(self)

        # This is to work around a bug in current versions
        # of Python.  The bug has been reported, and fixed
        # in Python's CVS.
        self.wfile = cStringIO.StringIO()

        self.client_address = self.client_address.split(":")

        self.out_msg    = Response()
        self.user       = None
        self.op         = None
        self.op_arg     = None
        self.out_code   = None
        self.msg_thread = None

    def handle(self):
        try:
            self._really_handle()
        except UnsupportedVersionError, e:
            self.handle_error(505, "Version Not Supported: %s" % e)
        except NotImplementedError, e:
            self.handle_error(501, "Not implemented: %s" % e)
        except (ProtocolError, KeyError), e:
            # We assume that KeyErrors are due to not
            # finding a key in the RFC2822 message
            self.handle_error(400, "Bad request: %s" % e)
        except AuthorizationError, e:
            self.handle_error(401, "Unauthorized: %s" % e)
        except SignatureError, e:
            self.handle_error(401, "Unauthorized, Signature Error: %s" % e)
        except Exception, e:
            self.handle_error(500, "Internal Server Error: %s" % e)
            traceback.print_exc()

        self.out_msg.setdefault('Code', str(self.out_msg.ok_code))
        self.out_msg.setdefault('Diag', 'OK')
        self.out_msg.init_for_sending()

        self.usage_log.info("%s,%s,%s,%s,%d" %
                            (self.user, self.client_address[0], self.op,
                             repr(self.op_arg), int(self.out_msg['Code'])))

        self.log.debug("sending: %s" % self.out_msg)
        self.wfile.write(str(self.out_msg))

    def _really_handle(self):
        """handle() without the exception handling"""
        self.log.debug("received: %s" % repr(self.packet))
        signed_msg = MacEnvelope(self.rfile)
        self.user = signed_msg['User']
        if self.user != pyzor.anonymous_user:
            if self.server.passwd.has_key(self.user):
                signed_msg.verify_sig(self.server.passwd[self.user])
            else:
                raise SignatureError("unknown user")

        self.in_msg = signed_msg.get_submsg(pyzor.Request)
        self.msg_thread = self.in_msg.get_thread()

        # We take the int() of the proto versions because
        # if the int()'s are the same, then they should be compatible
        if int(self.in_msg.get_protocol_version()) != int(proto_version):
            raise UnsupportedVersionError()

        self.out_msg.set_thread(self.msg_thread)

        self.op = Opname(self.in_msg.get_op())
        if not self.server.acl.allows(self.user, self.op):
            raise AuthorizationError("user is unauthorized to request the "
                                     "operation")

        self.log.debug("got a %s command from %s" %
                       (self.op, self.client_address))

        if not self.dispatches.has_key(self.op):
            raise NotImplementedError("requested operation is not "
                                      "implemented")

        dispatch = self.dispatches[self.op]
        if dispatch is not None:
            apply(dispatch, (self,))

    def handle_error(self, code, s):
        self.out_msg = ErrorResponse(code, s)
        if self.msg_thread is None:
            self.out_msg.set_thread(ThreadId(0))
        else:
            self.out_msg.set_thread(self.msg_thread)

    def handle_check(self):
        digest = self.in_msg['Op-Digest']
        self.op_arg = digest
        self.log.debug("request to check digest %s" % digest)
        try:
            rec = self.db[digest]
        except KeyError:
            r_count  = 0
            wl_count = 0
        else:
            r_count  = rec.r_count
            wl_count = rec.wl_count
        self.out_msg['Count']    = "%d" % r_count
        self.out_msg['WL-Count'] = "%d" % wl_count

    def handle_report(self):
        digest = self.in_msg['Op-Digest']
        self.op_arg = digest
        self.log.debug("request to report digest %s" % digest)
        try:
            rec = self.db[digest]
        except KeyError:
            rec = pyzor.server_engines.Record()
        rec.r_increment()
        self.db[digest] = rec

    def handle_whitelist(self):
        digest = self.in_msg['Op-Digest']
        self.op_arg = digest
        self.log.debug("request to whitelist digest %s" % digest)
        try:
            rec = self.db[digest]
        except KeyError:
            rec = pyzor.server_engines.Record()
        rec.wl_increment()
        self.db[digest] = rec

    def handle_info(self):
        digest = self.in_msg['Op-Digest']
        self.op_arg = digest
        self.log.debug("request to check digest %s" % digest)
        try:
            rec = self.db[digest]
        except KeyError:
            rec = pyzor.server_engines.Record()
        def time_output(t):
            if not t:
                return 0
            return time.mktime(t.timetuple())
        self.out_msg['Entered'] = "%d" % time_output(rec.r_entered)
        self.out_msg['Updated'] = "%d" % time_output(rec.r_updated)
        self.out_msg['WL-Entered'] = "%d" % time_output(rec.wl_entered)
        self.out_msg['WL-Updated'] = "%d" % time_output(rec.wl_updated)
        self.out_msg['Count']    = "%d" % rec.r_count
        self.out_msg['WL-Count'] = "%d" % rec.wl_count

    dispatches = { 'check':     handle_check,
                   'report':    handle_report,
                   'ping':      None,
                   'info':      handle_info,
                   'whitelist': handle_whitelist,
                   }
