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
__revision__ = "$Id: server.py,v 1.11 2002-05-08 03:26:23 ftobin Exp $"


class AuthorizationError(Exception):
    """signature was valid, but not permitted to
    do the requested action"""
    pass


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
    max_age = 72*3600

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
        except AuthorizationError:
            self.handle_error(401, "Unauthorized")
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

    def _really_handle(self):
        """handle() without the exception handling"""

        self.output.debug("received: %s" % repr(self.packet))
        
        signed_msg = MacEnvelope(self.rfile)

        self.user = signed_msg.get('User', None)

        if self.user:
            raise NotImplementedError
            user_key    = None
            signed_msg.verify_sig(user_key)

        self.in_msg = signed_msg.get_submsg(pyzor.Request)

        # We take the int() of the proto versions because
        # if the int()'s are the same, then they should be compatible
        if int(self.in_msg.get_protocol_version()) != int(proto_version):
            raise UnsupportedVersionError
        
        self.msg_thread = self.in_msg.get_thread()
        self.out_msg.set_thread(self.msg_thread)

        self.op = self.in_msg.get_op()
        
        self.output.debug("got a %s command from %s" %
                          (self.op, self.client_address))
            
        if self.op == 'ping':
            pass
        elif self.op == 'check':
            self.handle_check()
        elif self.op == 'report':
            self.handle_report()
        else:
            raise NotImplementedError, self.op
        

    def handle_error(self, code, s):
        self.out_msg = ErrorResponse(code, s)
        if self.msg_thread is not None:
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

        assert isinstance(count, int) or isinstance(count, long)
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
