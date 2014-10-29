"""Redis database engine.

XXX Deprecated version.
"""

import logging
import datetime
import functools

try:
    import redis

    _has_redis = True
except ImportError:
    redis = None
    _has_redis = False

from pyzor.engines.common import *

NAMESPACE = "pyzord.digest"

encode_date = lambda d: "" if d is None else d.strftime("%Y-%m-%d %H:%M:%S")
decode_date = lambda x: None if x == "" else datetime.datetime.strptime(
    x, "%Y-%m-%d %H:%M:%S")


def safe_call(f):
    """Decorator that wraps a method for handling database operations."""

    def wrapped_f(self, *args, **kwargs):
        # This only logs the error and raise the usual Error for consistency,
        # the redis library takes care of reconnecting and everything else.
        try:
            return f(self, *args, **kwargs)
        except redis.exceptions.RedisError as e:
            self.log.error("Redis error while calling %s: %s",
                           f.__name__, e)
            raise DatabaseError("Database temporarily unavailable.")

    return wrapped_f


class RedisDBHandle(BaseEngine):
    absolute_source = False
    handles_one_step = False

    log = logging.getLogger("pyzord")

    def __init__(self, fn, mode, max_age=None):
        self.max_age = max_age
        # The 'fn' is host,port,password,db.  We ignore mode.
        # We store the authentication details so that we can reconnect if
        # necessary.
        fn = fn.split(",")
        self.host = fn[0] or "localhost"
        self.port = fn[1] or "6379"
        self.passwd = fn[2] or None
        self.db_name = fn[3] or "0"
        self.db = self._get_new_connection()

    @staticmethod
    def _encode_record(r):
        return ("%s,%s,%s,%s,%s,%s" %
                (r.r_count,
                 encode_date(r.r_entered),
                 encode_date(r.r_updated),
                 r.wl_count,
                 encode_date(r.wl_entered),
                 encode_date(r.wl_updated))).encode()

    @staticmethod
    def _decode_record(r):
        if r is None:
            return Record()
        fields = r.decode().split(",")
        return Record(r_count=int(fields[0]),
                      r_entered=decode_date(fields[1]),
                      r_updated=decode_date(fields[2]),
                      wl_count=int(fields[3]),
                      wl_entered=decode_date(fields[4]),
                      wl_updated=decode_date(fields[5]))

    def __iter__(self):
        for key in self.db.keys(self._real_key("*")):
            yield key.rsplit(".", 1)[-1]

    def _iteritems(self):
        for key in self:
            try:
                yield key, self[key]
            except Exception as ex:
                self.log.warning("Invalid record %s: %s", key, ex)

    def iteritems(self):
        return self._iteritems()

    def items(self):
        return list(self._iteritems())

    @staticmethod
    def _real_key(key):
        return "%s.%s" % (NAMESPACE, key)

    @safe_call
    def _get_new_connection(self):
        if "/" in self.host:
            return redis.StrictRedis(unix_socket_path=self.host,
                                     db=int(self.db_name), password=self.passwd)
        return redis.StrictRedis(host=self.host, port=int(self.port),
                                 db=int(self.db_name), password=self.passwd)

    @safe_call
    def __getitem__(self, key):
        return self._decode_record(self.db.get(self._real_key(key)))

    @safe_call
    def __setitem__(self, key, value):
        if self.max_age is None:
            self.db.set(self._real_key(key), self._encode_record(value))
        else:
            self.db.setex(self._real_key(key), self.max_age,
                          self._encode_record(value))

    @safe_call
    def __delitem__(self, key):
        self.db.delete(self._real_key(key))

    @classmethod
    def get_prefork_connections(cls, fn, mode, max_age=None):
        """Yields a number of database connections suitable for a Pyzor
        pre-fork server.
        """
        while True:
            yield functools.partial(cls, fn, mode, max_age=max_age)


class ThreadedRedisDBHandle(RedisDBHandle):
    def __init__(self, fn, mode, max_age=None, bound=None):
        RedisDBHandle.__init__(self, fn, mode, max_age=max_age)


if not _has_redis:
    handle = DBHandle(single_threaded=None,
                      multi_threaded=None,
                      multi_processing=None,
                      prefork=None)
else:
    handle = DBHandle(single_threaded=RedisDBHandle,
                      multi_threaded=ThreadedRedisDBHandle,
                      multi_processing=None,
                      prefork=RedisDBHandle)
