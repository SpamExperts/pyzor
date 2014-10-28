"""MySQLdb database engine."""

import time
import logging
import datetime
import itertools
import functools
import threading

try:
    import Queue
except ImportError:
    import queue as Queue

try:
    import MySQLdb
    import MySQLdb.cursors
    _has_mysql = True
except ImportError:
    _has_mysql = False

from pyzor.engines.common import *


class MySQLDBHandle(BaseEngine):
    absolute_source = False
    handles_one_step = True
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
    reorganize_period = 3600 * 24  # 1 day
    reconnect_period = 60  # seconds
    log = logging.getLogger("pyzord")

    def __init__(self, fn, mode, max_age=None):
        self.max_age = max_age
        self.db = None
        # The 'fn' is host,user,password,db,table.  We ignore mode.
        # We store the authentication details so that we can reconnect if
        # necessary.
        self.host, self.user, self.passwd, self.db_name, \
            self.table_name = fn.split(",")
        self.last_connect_attempt = 0  # We have never connected.
        self.reorganize_timer = None
        self.reconnect()
        self.start_reorganizing()

    def _get_new_connection(self):
        """Returns a new db connection."""
        db = MySQLdb.connect(host=self.host, user=self.user,
                             db=self.db_name, passwd=self.passwd)
        db.autocommit(True)
        return db

    def _check_reconnect_time(self):
        if time.time() - self.last_connect_attempt < self.reconnect_period:
            # Too soon to reconnect.
            self.log.debug("Can't reconnect until %s",
                           (time.ctime(self.last_connect_attempt +
                                       self.reconnect_period)))
            return False
        return True

    def reconnect(self):
        if not self._check_reconnect_time():
            return
        if self.db:
            try:
                self.db.close()
            except MySQLdb.Error:
                pass
        try:
            self.db = self._get_new_connection()
        except MySQLdb.Error as e:
            self.log.error("Unable to connect to database: %s", e)
            self.db = None
        # Keep track of when we connected, so that we don't retry too often.
        self.last_connect_attempt = time.time()

    def _iter(self, db):
        c = db.cursor(cursorclass=MySQLdb.cursors.SSCursor)
        c.execute("SELECT digest FROM %s" % self.table_name)
        while True:
            row = c.fetchone()
            if not row:
                break
            yield row[0]
        c.close()

    def __iter__(self):
        return self._safe_call("iter", self._iter, ())

    def _iteritems(self, db):
        c = db.cursor(cursorclass=MySQLdb.cursors.SSCursor)
        c.execute("SELECT digest, r_count, wl_count, r_entered, r_updated, "
                  "wl_entered, wl_updated FROM %s" % self.table_name)
        while True:
            row = c.fetchone()
            if not row:
                break
            yield row[0], Record(*row[1:])
        c.close()

    def iteritems(self):
        return self._safe_call("iteritems", self._iteritems, ())

    def items(self):
        return list(self._safe_call("iteritems", self._iteritems, ()))

    def __del__(self):
        """Close the database when the object is no longer needed."""
        try:
            if self.db:
                self.db.close()
        except MySQLdb.Error:
            pass

    def _safe_call(self, name, method, args):
        try:
            return method(*args, db=self.db)
        except (MySQLdb.Error, AttributeError) as ex:
            self.log.error("%s failed: %s", name, ex)
            self.reconnect()
            # Retrying just complicates the logic - we don't really care if
            # a single query fails (and it's possible that it would fail)
            # on the second attempt anyway.  Any exceptions are caught by
            # the server, and a 'nice' message provided to the caller.
            raise DatabaseError("Database temporarily unavailable.")

    def report(self, keys):
        return self._safe_call("report", self._report, (keys,))

    def whitelist(self, keys):
        return self._safe_call("whitelist", self._whitelist, (keys,))

    def __getitem__(self, key):
        return self._safe_call("getitem", self._really__getitem__, (key,))

    def __setitem__(self, key, value):
        return self._safe_call("setitem", self._really__setitem__,
                               (key, value))

    def __delitem__(self, key):
        return self._safe_call("delitem", self._really__delitem__, (key,))

    def _report(self, keys, db=None):
        c = db.cursor()
        try:
            c.executemany("INSERT INTO %s (digest, r_count, wl_count, "
                          "r_entered, r_updated, wl_entered, wl_updated) "
                          "VALUES (%%s, 1, 0, NOW(), NOW(), NOW(), NOW()) ON "
                          "DUPLICATE KEY UPDATE r_count=r_count+1, "
                          "r_updated=NOW()" % self.table_name,
                          itertools.imap(lambda key: (key,), keys))
        finally:
            c.close()

    def _whitelist(self, keys, db=None):
        c = db.cursor()
        try:
            c.executemany("INSERT INTO %s (digest, r_count, wl_count, "
                          "r_entered, r_updated, wl_entered, wl_updated) "
                          "VALUES (%%s, 0, 1, NOW(), NOW(), NOW(), NOW()) ON "
                          "DUPLICATE KEY UPDATE wl_count=wl_count+1, "
                          "wl_updated=NOW()" % self.table_name,
                          itertools.imap(lambda key: (key,), keys))
        finally:
            c.close()

    def _really__getitem__(self, key, db=None):
        """__getitem__ without the exception handling."""
        c = db.cursor()
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

    def _really__setitem__(self, key, value, db=None):
        """__setitem__ without the exception handling."""
        c = db.cursor()
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
        finally:
            c.close()

    def _really__delitem__(self, key, db=None):
        """__delitem__ without the exception handling."""
        c = db.cursor()
        try:
            c.execute("DELETE FROM %s WHERE digest=%%s" % self.table_name,
                      (key,))
        finally:
            c.close()

    def start_reorganizing(self):
        if not self.max_age:
            return
        self.log.debug("reorganizing the database")
        breakpoint = (datetime.datetime.now() -
                      datetime.timedelta(seconds=self.max_age))
        db = self._get_new_connection()
        c = db.cursor()
        try:
            c.execute("DELETE FROM %s WHERE r_updated<%%s" %
                      self.table_name, (breakpoint,))
        except (MySQLdb.Error, AttributeError) as e:
            self.log.warn("Unable to reorganise: %s", e)
        finally:
            c.close()
            db.close()
        self.reorganize_timer = threading.Timer(self.reorganize_period,
                                                self.start_reorganizing)
        self.reorganize_timer.setDaemon(True)
        self.reorganize_timer.start()

    @classmethod
    def get_prefork_connections(cls, fn, mode, max_age=None):
        """Yields a number of database connections suitable for a Pyzor
        pre-fork server.
        """
        # Only run the reorganize timer in the first child process.
        yield functools.partial(cls, fn, mode, max_age=max_age)
        while True:
            yield functools.partial(cls, fn, mode, max_age=None)


class ThreadedMySQLDBHandle(MySQLDBHandle):
    def __init__(self, fn, mode, max_age=None, bound=None):
        self.bound = bound
        if self.bound:
            self.db_queue = Queue.Queue()
        MySQLDBHandle.__init__(self, fn, mode, max_age=max_age)

    def _get_connection(self):
        if self.bound:
            return self.db_queue.get()
        else:
            return self._get_new_connection()

    def _release_connection(self, db):
        if self.bound:
            self.db_queue.put(db)
        else:
            db.close()

    def _safe_call(self, name, method, args):
        db = self._get_connection()
        try:
            return method(*args, db=db)
        except (MySQLdb.Error, AttributeError) as ex:
            self.log.error("%s failed: %s", name, ex)
            if not self.bound:
                raise DatabaseError("Database temporarily unavailable.")
            try:
                # Connection might be timeout, ping and retry
                db.ping(True)
                return method(*args, db=db)
            except (MySQLdb.Error, AttributeError) as ex:
                # attempt a new connection, if we can retry
                db = self._reconnect(db)
                raise DatabaseError("Database temporarily unavailable.")
        finally:
            self._release_connection(db)

    def reconnect(self):
        if not self.bound:
            return
        for _ in xrange(self.bound):
            self.db_queue.put(self._get_new_connection())

    def _reconnect(self, db):
        if not self._check_reconnect_time():
            return db
        else:
            self.last_connect_attempt = time.time()
            return self._get_new_connection()

    def __del__(self):
        if not self.bound:
            return
        for db in iter(self.db_queue.get_nowait):
            try:
                db.close()
            except MySQLdb.Error:
                continue
            except Queue.Empty:
                break


class ProcessMySQLDBHandle(MySQLDBHandle):
    def __init__(self, fn, mode, max_age=None):
        MySQLDBHandle.__init__(self, fn, mode, max_age=max_age)

    def reconnect(self):
        pass

    def __del__(self):
        pass

    def _safe_call(self, name, method, args):
        db = None
        try:
            db = self._get_new_connection()
            return method(*args, db=db)
        except (MySQLdb.Error, AttributeError) as ex:
            self.log.error("%s failed: %s", name, ex)
            raise DatabaseError("Database temporarily unavailable.")
        finally:
            if db is not None:
                db.close()

if not _has_mysql:
    handle = DBHandle(single_threaded=None,
                      multi_threaded=None,
                      multi_processing=None,
                      prefork=None)
else:
    handle = DBHandle(single_threaded=MySQLDBHandle,
                      multi_threaded=ThreadedMySQLDBHandle,
                      multi_processing=ProcessMySQLDBHandle,
                      prefork=MySQLDBHandle)
