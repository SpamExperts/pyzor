"""networked spam-signature detection server

Copyright (C) 2002 Frank J. Tobin <ftobin@neverending.org>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, visit the following URL:
http://www.gnu.org/copyleft/gpl.html
"""

from __future__ import division

import SocketServer
import time
import gdbm
import StringIO
import traceback
import threading

import pyzor
from pyzor import *

__author__   = pyzor.__author__
__version__  = pyzor.__version__
__revision__ = "$Id: server.py,v 1.7 2002-04-14 22:23:08 ftobin Exp $"


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

    def cleanup(self, max_age=(48*3600)):
        """max_age is in seconds"""
        self.output.debug("cleaning up the database")
        key = self.db.firstkey()
        breakpoint = time.time() - max_age*3600

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

    def __init__(self, address, debug=None):
        RequestHandler.output = Output(debug=debug)
        super(Server, self).__init__(address, RequestHandler)
        self.ensure_db_exists()
        

    def ensure_db_exists(self):
        db = DBHandle('c')


class RequestHandler(SocketServer.DatagramRequestHandler, object):
    def setup(self):
        super(RequestHandler, self).setup()

        # This is to mask what I think is a bug in
        # SocketServer.DatagramRequestHandler.setup, where it
        # initializes the wfile from self.packet
        self.wfile = StringIO.StringIO()
        self.msg = Message(thread=0)

    def handle(self):
        try:
            self.expect(proto_name, read_netstring)
            self.expect(proto_version, read_netstring)
            thread_id = self.read_thread()
            self.msg.thread = thread_id

            op = self.read_string()
            self.output.debug("got a %s command from %s" %
                              (op, self.client_address))
            if op == 'ping':
                pass
            elif op == 'check':
                self.handle_check()
            elif op == 'report':
                self.handle_report()
            else:
                raise NotImplementedError, op
        except NotImplementedError, e:
            self.handle_error(501, "Not implemented: %s" % e)
        except ProtocolError, e:
            self.handle_error(400, "Bad request: %s" % e)
            traceback.print_exc()
        except TimeoutError, e:
            self.handle_error(503, "Gateway timeout: %s" % e)
        except Exception, e:
            self.handle_error(500, "Internal Server Error: %s" % e)
            traceback.print_exc()
        else:
            if not self.msg:
                self.handle_error(200, "OK")

        self.output.debug("sending: %s" % repr(str(self.msg)))
        self.wfile.write(str(self.msg))

    def handle_error(self, code, s):
        self.msg.clear()
        self.msg.add_int(code)
        self.msg.add_string(s)

    def handle_check(self):
        ttl    = self.read_ttl()
        digest = self.read_digest()
        self.output.debug("request is for digest %s" % digest)
        self.msg.add_int(200)

        db = DBHandle('r')
        if db.has_key(digest):
            self.msg.add_int(Record.from_str(db[digest]).count)
        else:
            self.msg.add_int(0)

    def handle_report(self):
        ttl    = self.read_ttl()
        spec   = self.read_digest_spec()
        digest = self.read_digest()
        self.output.debug("request is for digest %s" % digest)

        db = DBHandle('c')
        if not db.has_key(digest):
            db[digest] = str(Record())
        rec = Record.from_str(db[digest])
        rec.increment()
        db[digest] = str(rec)

    def read_ttl(self):
        x = self.read_int()
        #self.output.debug("read ttl %s" % x)
        return x

    def read_digest(self):
        try:
            x = PiecesDigest(self.read_string())
            #self.output.debug("read digest %s" % x)
        except ValueError, e:
            raise ProtocolError, e
        return x

    def read_digest_spec(self):
        try:
            return PiecesDigestSpec(self.read_list(read_netstring))
        except ValueError, e:
            raise ProtocolError, e

    def read_digest(self):
        try:
            return PiecesDigest(self.read_string())
        except ValueError, e:
            raise ProtocolError, e

    def read_thread(self):
        try:
            return ThreadID(self.read_int())
        except ValueError, e:
            raise ProtocolError, e

    def read_string(self):
        s = read_netstring(self.rfile)
        #self.output.debug("read string %s" % repr(s))
        return s

    def read_int(self):
        i = read_netint(self.rfile)
        #self.output.debug("read int %s" % repr(i))
        return i

    def read_list(self, factory):
        l = read_netlist(self.rfile, factory)
        #self.output.debug("read list %s" % repr(l))
        return l

    def expect(self, expected, factory):
        got = apply(factory, (self.rfile,))
        if got != expected:
            raise ProtocolError, \
                  "expected %s, got %s" % (repr(expected), repr(got))
