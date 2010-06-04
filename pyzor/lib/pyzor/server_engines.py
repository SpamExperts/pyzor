"""Database backends for pyzord.

The database class must expose a dictionary-like interface, allowing access
via __getitem__, __setitem__, and __delitem__.  The key will be a forty
character string, and the value should be an instance of the Record class.

If the database backend cannot store the Record objects natively, then it
must transparently take care of translating to/from Record objects in
__setitem__ and __getitem__.

The database class should take care of expiring old values at the
appropriate interval.
"""

import sys
import gdbm
import time
import logging
import datetime
import threading

try:
    import MySQLdb
except ImportError:
    # The SQL database backend will not work.
    MySQLdb = None

database_classes = {}

class DatabaseError(Exception):
    pass


class Record(object):
    """Prefix conventions used in this class:
    r = report (spam)
    wl = whitelist
    """
    def __init__(self, r_count=0, wl_count=0, r_entered=None,
                 r_updated=None, wl_entered=None, wl_updated=None):
        self.r_count =  r_count
        self.wl_count = wl_count
        self.r_entered = r_entered
        self.r_updated = r_updated
        self.wl_entered = wl_entered
        self.wl_updated = wl_updated

    def wl_increment(self):
        # overflow prevention
        if self.wl_count < sys.maxint:
            self.wl_count += 1
        if self.wl_entered is None:
            self.wl_entered = datetime.datetime.now()
        self.wl_update()

    def r_increment(self):
        # overflow prevention
        if self.r_count < sys.maxint:
            self.r_count += 1
        if self.r_entered is None:
            self.r_entered = datetime.datetime.now()
        self.r_update()

    def r_update(self):
        self.r_updated = datetime.datetime.now()

    def wl_update(self):
        self.wl_updated = datetime.datetime.now()


class gdbmDBHandle(object):
    handles_threaded = True
    absolute_source = True
    db_lock   = threading.Lock()
    max_age   = 3600*24*30*4   # 3 months
    sync_period = 60
    reorganize_period = 3600*24  # 1 day
    fields = (
        'r_count',  'r_entered',  'r_updated',
        'wl_count', 'wl_entered', 'wl_updated',
        )
    this_version = '1'
    log = logging.getLogger("pyzord")
    db = None

    def __init__(self, fn, mode, max_age=None):
        if max_age is not None:
            self.max_age = max_age
        self.db = gdbm.open(fn, mode)
        self.start_reorganizing()
        self.start_syncing()

    def apply_locking_method(self, method, varargs=(), kwargs=None):
        if kwargs is None:
            kwargs = {}
        self.log.debug("acquiring lock")
        self.db_lock.acquire()
        self.log.debug("acquired lock")
        try:
            result = apply(method, varargs, kwargs)
        finally:
            self.log.debug("releasing lock")
            self.db_lock.release()
            self.log.debug("released lock")
        return result

    def __getitem__(self, key):
        return self.apply_locking_method(self._really_getitem, (key,))

    def _really_getitem(self, key):
        return self.decode_record(self.db[key])

    def __setitem__(self, key, value):
        self.apply_locking_method(self._really_setitem, (key, value))

    def _really_setitem(self, key, value):
        self.db[key] = self.encode_record(value)

    def __delitem__(self, key):
        self.apply_locking_method(self._really_delitem, (key,))

    def _really_delitem(self, key):
        del self.db[key]

    def start_syncing(self):
        if self.db:
            self.apply_locking_method(self._really_sync)
        self.sync_timer = threading.Timer(self.sync_period,
                                          self.start_syncing)
        self.sync_timer.start()

    def _really_sync(self):
        self.db.sync()

    def start_reorganizing(self):
        if self.db:
            self.apply_locking_method(self._really_reorganize)
        self.reorganize_timer = threading.Timer(self.reorganize_period,
                                                self.start_reorganizing)
        self.reorganize_timer.start()

    def _really_reorganize(self):
        self.log.debug("reorganizing the database")
        key = self.db.firstkey()
        breakpoint = time.time() - self.max_age
        while key is not None:
            rec = self[key]
            delkey = None
            if rec.r_updated < breakpoint:
                self.log.debug("deleting key %s" % key)
                delkey = key
            key = self.db.nextkey(key)
            if delkey:
                del self[delkey]
        self.db.reorganize()
    _really_reorganize = classmethod(_really_reorganize)

    @classmethod
    def encode_record(cls):
        values = [cls.this_version]
        values.extend(["%d" % getattr(self, x) for x in self.fields])
        return ",".join(values)

    @classmethod
    def decode_record(cls, s):
        parts = s.split(',')
        dispatch = None
        version = parts[0]
        if len(parts) == 3:
            dispatch = cls.decode_record_0
        elif version == '1':
            dispatch = cls.decode_record_1
        else:
            raise StandardError("don't know how to handle db value %s" %
                                repr(s))
        return dispatch(s)

    @staticmethod
    def decode_record_0(s):
        r = Record()
        parts = s.split(',')
        fields = ('r_count', 'r_entered', 'r_updated')
        assert len(parts) == len(fields)
        for i in range(len(parts)):
            setattr(r, fields[i], int(parts[i]))
        return r

    @classmethod
    def decode_record_1(cls, s):
        r = Record()
        parts = s.split(',')[1:]
        assert len(parts) == len(self.fields)
        for i in range(len(parts)):
            setattr(r, self.fields[i], int(parts[i]))
        return r
database_classes["gdbm"] = gdbmDBHandle


class MySQLDBHandle(object):
    handles_threaded = False
    absolute_source = False
    # The table must already exist, and have this schema:
    #   CREATE TABLE `public` (
    #   `digest` char(40) default NULL,
    #   `r_count` int(11) default NULL,
    #   `wl_count` int(11) default NULL,
    #   `r_entered` datetime default NULL,
    #   `wl_entered` datetime default NULL,
    #   `r_updated` datetime default NULL,
    #   `wl_updated` datetime default NULL,
    #   PRIMARY KEY  (`digest`)
    #   )
    # XXX Re-organising might be faster with a r_updated index.  However,
    # XXX the re-organisation time isn't that important, and that would
    # XXX (slightly) slow down all inserts, so we leave it for now.
    max_age = 60*60*24*30*4       # Approximately 4 months
    reorganize_period = 3600*24   # 1 day
    reconnect_period = 60      # seconds
    log = logging.getLogger("pyzord")
    db = None

    def __init__(self, fn, mode, max_age=None):
        if max_age is not None:
            self.max_age = max_age
        # The 'fn' is host,user,password,db,table.  We ignore mode.
        # We store the authentication details so that we can reconnect if
        # necessary.
        self.host, self.user, self.passwd, self.db_name, \
            self.table_name = fn.split(",")
        self.last_connect_attempt = 0 # We have never connected.
        self.reconnect()
        self.start_reorganizing()

    def reconnect(self):
        if time.time() - self.last_connect_attempt < self.reconnect_period:
            # Too soon to reconnect.
            self.log.debug("Can't reconnect until %s" %
                           (time.ctime(self.last_connect_attempt +
                                       self.reconnect_period),))
            return
        if self.db:
            try:
                self.db.close()
            except MySQLdb.Error:
                pass
        try:
            self.db = MySQLdb.connect(host=self.host, user=self.user,
                                      db=self.db_name, passwd=self.passwd)
        except MySQLdb.Error, e:
            self.log.error("Unable to connect to database: %s" % (e,))
            self.db = None
        # Keep track of when we connected, so that we don't retry too often.
        self.last_connect_attempt = time.time()

    def __del__(self):
        """Close the database when the object is no longer needed."""
        try:
            self.db.close()
        except MySQLdb.Error:
            pass

    def _safe_call(self, name, method, args):
        try:
            return method(*args)
        except (MySQLdb.Error, AttributeError), e:
            self.log.error("%s failed: %s" % (name, e))
            self.reconnect()
            # Retrying just complicates the logic - we don't really care if
            # a single query fails (and it's possible that it would fail)
            # on the second attempt anyway.  Any exceptions are caught by
            # the server, and a 'nice' message provided to the caller.
            raise DatabaseError("Database temporarily unavailable.")

    def __getitem__(self, key):
        return self._safe_call("getitem", self._really__getitem__, (key,))

    def __setitem__(self, key, value):
        return self._safe_call("setitem", self._really__setitem__,
                               (key, value))

    def __delitem__(self, key):
        return self._safe_call("delitem", self._really__delitem__, (key,))

    def _really__getitem__(self, key):
        """__getitem__ without the exception handling."""
        if not self.db:
            assert False, "Can't connect to database."
        c = self.db.cursor()
        # The order here must match the order of the arguments to the
        # Record constructor.
        c.execute("SELECT r_count, wl_count, r_entered, r_updated, "
                  "wl_entered, wl_updated FROM %s WHERE digest=%%s" %
                  self.table_name, (key,))
        try:
            try:
                return Record(*c.fetchone())
            except TypeError:
                # fetchone() returned None, i.e. there is no such record
                raise KeyError()
        finally:
            c.close()

    def _really__setitem__(self, key, value):
        """__setitem__ without the exception handling."""
        c = self.db.cursor()
        try:
            c.execute("INSERT INTO %s (digest, r_count, wl_count, "
                      "r_entered, r_updated, wl_entered, wl_updated) "
                      "VALUES (%%s, %%s, %%s, %%s, %%s, %%s, %%s) ON "
                      "DUPLICATE KEY UPDATE r_count=%%s, wl_count=%%s, "
                      "r_entered=%%s, r_updated=%%s, wl_entered=%%s, "
                      "wl_updated=%%s" % self.table_name,
                      (key, value.r_count, value.wl_count, value.r_entered,
                       value.r_updated, value.wl_entered, value.wl_updated,
                       value.r_count, value.wl_count, value.r_entered,
                       value.r_updated, value.wl_entered, value.wl_updated))
            self.db.commit()
        finally:
            c.close()

    def _really__delitem__(self, key):
        """__delitem__ without the exception handling."""
        c = self.db.cursor()
        try:
            c.execute("DELETE FROM %s WHERE digest=%%s" % self.table_name,
                      (key,))
            self.db.commit()
        finally:
            c.close()

    def start_reorganizing(self):
        self.log.debug("reorganizing the database")
        breakpoint = datetime.datetime.now() - \
            datetime.timedelta(seconds=self.max_age)
        try:
            c = self.db.cursor()
            c.execute("DELETE FROM %s WHERE r_updated<%%s" %
                      self.table_name, (breakpoint,))
            c.close()
        except (MySQLdb.Error, AttributeError), e:
            self.log.warn("Unable to reorganise: %s" % (e,))
        self.reorganize_timer = threading.Timer(self.reorganize_period,
                                                self.start_reorganizing)
        self.reorganize_timer.start()
database_classes["mysql"] = MySQLDBHandle
