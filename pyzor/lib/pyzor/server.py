"""networked spam-signature detection server"""

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


from __future__ import division

import os
import signal
import SocketServer
import time
import gdbm
import cStringIO
import traceback
import threading

import pyzor
from pyzor import *

__author__   = pyzor.__author__
__version__  = pyzor.__version__
__revision__ = "$Id: server.py,v 1.16 2002-06-17 17:18:08 ftobin Exp $"


class AuthorizationError(pyzor.CommError):
    """signature was valid, but not permitted to
    do the requested action"""
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
        typecheck(user, Username)
        typecheck(op,   Opname)
        
        for entry in self.entries:
            if entry.allows(user, op):
                return True
            if entry.denies(user, op):
                return False
        return self.default_allow


class ACLEntry(tuple):
    all_keyword = 'all'.lower()
    
    def __init__(self, v):
        (user, op, allow) = v
        typecheck(user,  Username)
        typecheck(op,    Opname)
        assert bool(allow) == allow

    def user(self):
        return self[0]
    user = property(user)

    def op(self):
        return self[1]
    op = property(op)

    def allow(self):
        return self[2]
    allow = property(allow)

    def allows(self, user, op):
        return self._says(user, op, True)

    def denies(self, user, op):
        return self._says(user, op, False)

    def _says(self, user, op, allow):
        """If allow is True, we return true if and only if we allow user to do op.
        If allow is False, we return true if and only if we deny user to do op
        """
        typecheck(user,  Username)
        typecheck(op,    Opname)
        assert bool(allow) == allow
        
        return (self.allow == allow
                and (self.user == user
                     or self.user.lower() == self.all_keyword)
                and (self.op == op
                     or self.op.lower() == self.all_keyword))



class AccessFile(object):
    # I started doing an iterator protocol for this, but it just
    # got too complicated keeping track of everything on the line
    __slots__ = ['file', 'output', 'lineno']
    allow_keyword = 'allow'
    deny_keyword = 'deny'
    
    def __init__(self, f):
        self.output = Output()
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
                self.output.warn("access file: invalid number of parts in line %d"
                                 % self.lineno)
                continue
            
            (ops_str, users_str, allow_str) = parts

            ops = []
            for op_str in ops_str.split():
                try:
                    op = Opname(op_str)
                except ValueError, e:
                    self.output.warn("access file: invalid opname %s line %d: %s"
                                     % (repr(op_str), self.lineno, e))
                else:
                    ops.append(op)

            users = []
            for u in users_str.split():
                try:
                    user = Username(u)
                except ValueError, e:
                    self.output.warn("access file: invalid username %s line %d: %s"
                                     % (repr(u), self.lineno, e))
                else:
                    users.append(user)

            allow_str = allow_str.strip()
            if allow_str.lower() == self.allow_keyword:
                allow = True
            elif allow_str.lower() == self.deny_keyword:
                allow = False
            else:
                self.output.warn("access file: invalid allow/deny keyword %s line %d"
                                 % (repr(allow_str), self.lineno))
                continue

            for op in ops:
                for user in users:
                    acl.add_entry(ACLEntry((user, op, allow)))



class Passwd(dict):
    def __setitem__(self, k, v):
        typecheck(k, pyzor.Username)
        typecheck(v, long)
        super(Passwd, self).__setitem__(k, v)


            
class PasswdFile(object):
    """Iteration gives (Username, long) objects

    Format of file is:
    user : key
    """
    __slots__ = ['file', 'output', 'lineno']

    def __init__(self, f):
        self.file = f
        self.output = Output()
        self.lineno = 0

    def __iter__(self):
        return self

    def next(self):
        while 1:
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
                self.output.warn("passwd line %d is invalid (wrong number of parts)"
                                 % self.lineno)
                continue
            
            try:
                return (Username(fields[0]), long(fields[1], 16))
            except ValueError, e:
                self.output.warn("invalid passwd entry line %d: %s"
                                 % (self.lineno, e))



class Log(object):
    __slots__ = ['fp']
    
    def __init__(self, fp=None):
        self.fp = fp

    def log(self, address, user=None, command=None, arg=None):
        # we don't use defaults because we want to be able
        # to pass in None
        if user    is None: user = ''
        if command is None: command = ''
        if arg     is None: arg = ''
        
        # We duplicate the time field merely so that
        # humans can peruse through the entries without processing
        ts = int(time.time())
        if self.fp is not None:
            self.fp.write("%s\n" %
                          ','.join((str(ts),
                                    time.ctime(ts),
                                    user,
                                    address[0],
                                    command,
                                    repr(arg))))
            self.fp.flush()



class Record(object):
    __slots__ = ['count', 'entered', 'updated']
    def __init__(self, count=0, entered=None, updated=None):
        if entered is None: entered = int(time.time())
        if updated is None: updated = entered
        self.count =   long(count)
        self.entered = int(entered)
        self.updated = int(updated)

    def increment(self):
        # overflow prevention
        if self.count < 2**30:
            self.count += 1
        self.update()

    def update(self):
        self.updated = int(time.time())

    def __str__(self):
        return "%d,%d,%d" % (self.count, self.entered, self.updated)

    def from_str(self, s):
        return apply(self, tuple(map(int, s.split(',', 3))))
    from_str = classmethod(from_str)



class DBHandle(object):
    __slots__ = ['db', 'output']
    dbfile = None
    db_lock = threading.Lock()
    max_age = 3600*24*30*4   # 3 months

    def __init__(self, mode='r'):
        self.output = Output()
        self.db_lock.acquire()
        self.db = gdbm.open(self.dbfile, mode)
        
    def __del__(self):
        self.db.sync()
        self.db_lock.release()

    def __getitem__(self, key):
        return self.db[key]

    def __setitem__(self, key, value):
        self.db[key] = value

    def has_key(self, key):
        return self.__contains__(key)

    def __contains__(self, key):
        return self.db.has_key(key)

    def cleanup(self):
        self.output.debug("cleaning up the database")
        key = self.db.firstkey()
        breakpoint = time.time() - self.max_age

        while key is not None:
            rec = Record.from_str(self[key])
            delkey = None
            if rec.updated < breakpoint:
                self.output.debug("deleting key %s" % key)
                delkey = key
            key = self.db.nextkey(key)
            if delkey:
                del self.db[delkey]
        
        self.db.reorganize()
        self.db.sync()

        

class Server(SocketServer.ThreadingUDPServer, object):
    ttl = 4
    timeout = 3
    max_packet_size = 8192
    time_diff_allowance = 180

    def __init__(self, address, log):
        self.output = Output()
        RequestHandler.output = self.output
        RequestHandler.log    = log

        self.output.debug('listening on %s' % str(address))
        super(Server, self).__init__(address, RequestHandler)

        self.ensure_db_exists()

    def ensure_db_exists(self):
        db = DBHandle('c')

    def serve_forever(self):
        self.pid = os.getpid()
        super(Server, self).serve_forever()



class RequestHandler(SocketServer.DatagramRequestHandler, object):
    def setup(self):
        super(RequestHandler, self).setup()

        # This is to work around a bug in current versions
        # of Python.  The bug has been reported, and fixed
        # in Python's CVS.
        self.wfile = cStringIO.StringIO()

        self.client_address = Address(self.client_address)
        
        self.out_msg    = Response()
        self.user       = None
        self.op         = None
        self.op_arg     = None
        self.msg_thread = None


    def handle(self):
        do_exit = False
        
        try:
            self._really_handle()
        except UnsupportedVersionError, e:
            self.handle_error(505, "Version Not Supported: %s" % e)
        except NotImplementedError, e:
            self.handle_error(501, "Not implemented: %s" % e)
        except KeyError, e:
            # We assume that KeyErrors are due to not
            # finding a key in the RFC822 message
            self.handle_error(400, "Bad request: %s" % e)
        except ProtocolError, e:
            self.handle_error(400, "Bad request: %s" % e)
        except TimeoutError, e:
            self.handle_error(503, "Gateway timeout: %s" % e)
        except AuthorizationError, e:
            self.handle_error(401, "Unauthorized: %s" % e)
        except SignatureError, e:
            self.handle_error(401, "Unauthorized, Signature Error: %s" % e)
        except SystemExit, e:
            do_exit = True
        except Exception, e:
            self.handle_error(500, "Internal Server Error: %s" % e)
            traceback.print_exc()

        self.out_msg.setdefault('Code', str(self.out_msg.ok_code))
        self.out_msg.setdefault('Diag', 'OK')
        self.out_msg.init_for_sending()

        self.log.log(self.client_address, self.user, self.op, self.op_arg)
        
        msg_str = str(self.out_msg)
        self.output.debug("sending: %s" % repr(msg_str))
        self.wfile.write(msg_str)
        
        if do_exit:
            db_hold = DBHandle('r')  # to keep the db consistent
            self.finish()
            os.kill(self.server.pid, signal.SIGQUIT)

    def _really_handle(self):
        """handle() without the exception handling"""

        self.output.debug("received: %s" % repr(self.packet))
        
        signed_msg = MacEnvelope(self.rfile)

        self.user = Username(signed_msg['User'])

        if self.user != pyzor.anonymous_user:
            if self.server.passwd.has_key(self.user):
                signed_msg.verify_sig(self.server.passwd[self.user])
            else:
                raise SignatureError, "unknown user"
        
        self.in_msg = signed_msg.get_submsg(pyzor.Request)

        self.msg_thread = self.in_msg.get_thread()

        # We take the int() of the proto versions because
        # if the int()'s are the same, then they should be compatible
        if int(self.in_msg.get_protocol_version()) != int(proto_version):
            raise UnsupportedVersionError
        
        self.out_msg.set_thread(self.msg_thread)

        self.op = Opname(self.in_msg.get_op())
        if not self.server.acl.allows(self.user, self.op):
            raise AuthorizationError, "user is unauthorized to request the operation"
        
        self.output.debug("got a %s command from %s" %
                          (self.op, self.client_address))

        dispatches = { 'check':    self.handle_check,
                       'report':   self.handle_report,
                       'ping':     None,
                       'shutdown': self.handle_shutdown,
                       }
                       
        if not dispatches.has_key(self.op):
            raise NotImplementedError, "requested operation is not implemented"

        dispatch = dispatches[self.op]
        if dispatch is not None:
            apply(dispatch)


    def handle_error(self, code, s):
        self.out_msg = ErrorResponse(code, s)
        
        if self.msg_thread is None:
            self.out_msg.set_thread(ThreadId(0))
        else:
            self.out_msg.set_thread(self.msg_thread)


    def handle_check(self):
        digest = self.in_msg['Op-Digest']
        self.op_arg = digest
        self.output.debug("request to check digest %s" % digest)

        db = DBHandle('r')
        if db.has_key(digest):
            count = Record.from_str(db[digest]).count
        else:
            count = 0

        if not (isinstance(count, int) or isinstance(count, long)):
            raise TypeError
        self.out_msg['Count'] = str(count)


    def handle_report(self):
        digest = self.in_msg['Op-Digest']
        self.op_arg = digest
        self.output.debug("request to report digest %s" % digest)

        db = DBHandle('c')
        if not db.has_key(digest):
            db[digest] = str(Record())
        rec = Record.from_str(db[digest])
        rec.increment()
        db[digest] = str(rec)


    def handle_shutdown(self):
        raise SystemExit
