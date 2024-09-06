"""Test the pyzor.engines.gdbm_ module."""
import time
import logging
import unittest

from datetime import datetime

try:
    from unittest.mock import Mock, patch, call
except ImportError:
    from mock import Mock, patch, call

import pyzor.engines.redis_
import pyzor.engines.common


class EncodingRedisTest(unittest.TestCase):
    """Test the RedisDBHandle class"""

    r_count = 24
    wl_count = 42
    entered = datetime(2014, 4, 23, 15, 41, 30)
    updated = datetime(2014, 4, 25, 17, 22, 25)
    wl_entered = datetime(2014, 2, 12, 11, 10, 55)
    wl_updated = datetime(2014, 3, 25, 5, 1, 50)

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.record = pyzor.engines.common.Record(
            self.r_count,
            self.wl_count,
            self.entered,
            self.updated,
            self.wl_entered,
            self.wl_updated,
        )
        self.entered_st = int(time.mktime(self.entered.timetuple()))
        self.updated_st = int(time.mktime(self.updated.timetuple()))
        self.wl_entered_st = int(time.mktime(self.wl_entered.timetuple()))
        self.wl_updated_st = int(time.mktime(self.wl_updated.timetuple()))

    def compare_records(self, r1, r2):
        attrs = (
            "r_count",
            "r_entered",
            "r_updated",
            "wl_count",
            "wl_entered",
            "wl_updated",
        )
        self.assertTrue(all(getattr(r1, attr) == getattr(r2, attr) for attr in attrs))

    def tearDown(self):
        unittest.TestCase.tearDown(self)

    def test_encode_record(self):
        expected = {
            "r_count": 24,
            "r_entered": self.entered_st,
            "r_updated": self.updated_st,
            "wl_count": 42,
            "wl_entered": self.wl_entered_st,
            "wl_updated": self.wl_updated_st,
        }
        result = pyzor.engines.redis_.RedisDBHandle._encode_record(self.record)
        self.assertEqual(result, expected)

    def test_encode_record_no_date(self):
        expected = {
            "r_count": 24,
            "r_entered": self.entered_st,
            "r_updated": 0,
            "wl_count": 42,
            "wl_entered": self.wl_entered_st,
            "wl_updated": self.wl_updated_st,
        }
        self.record.r_updated = None
        result = pyzor.engines.redis_.RedisDBHandle._encode_record(self.record)
        self.assertEqual(result, expected)

    def test_encode_record_no_white(self):
        expected = {
            "r_count": 24,
            "r_entered": self.entered_st,
            "r_updated": self.updated_st,
            "wl_count": 0,
            "wl_entered": 0,
            "wl_updated": 0,
        }
        self.record.wl_count = 0
        self.record.wl_entered = None
        self.record.wl_updated = None
        result = pyzor.engines.redis_.RedisDBHandle._encode_record(self.record)
        self.assertEqual(result, expected)

    def test_decode_record(self):
        encoded = {
            b"r_count": 24,
            b"r_entered": self.entered_st,
            b"r_updated": self.updated_st,
            b"wl_count": 42,
            b"wl_entered": self.wl_entered_st,
            b"wl_updated": self.wl_updated_st,
        }
        result = pyzor.engines.redis_.RedisDBHandle._decode_record(encoded)
        self.compare_records(result, self.record)

    def test_decode_record_no_date(self):
        encoded = {
            b"r_count": 24,
            b"r_entered": self.entered_st,
            b"r_updated": 0,
            b"wl_count": 42,
            b"wl_entered": self.wl_entered_st,
            b"wl_updated": self.wl_updated_st,
        }
        result = pyzor.engines.redis_.RedisDBHandle._decode_record(encoded)
        self.record.r_updated = None
        self.compare_records(result, self.record)

    def test_decode_record_no_white(self):
        encoded = {
            b"r_count": 24,
            b"r_entered": self.entered_st,
            b"r_updated": self.updated_st,
            b"wl_count": 0,
            b"wl_entered": 0,
            b"wl_updated": 0,
        }
        result = pyzor.engines.redis_.RedisDBHandle._decode_record(encoded)
        self.record.wl_count = 0
        self.record.wl_entered = None
        self.record.wl_updated = None
        self.compare_records(result, self.record)


class RedisTest(unittest.TestCase):
    max_age = 60 * 60

    def setUp(self):
        unittest.TestCase.setUp(self)
        logger = logging.getLogger("pyzord")
        logger.addHandler(logging.NullHandler())
        self.mredis = patch("pyzor.engines.redis_.redis", create=True).start()
        patch(
            "pyzor.engines.redis_.RedisDBHandle._encode_record", side_effect=lambda x: x
        ).start()
        patch(
            "pyzor.engines.redis_.RedisDBHandle._decode_record", side_effect=lambda x: x
        ).start()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_init(self):
        expected = {
            "host": "example.com",
            "port": 6387,
            "password": "passwd",
            "db": 5,
        }
        db = pyzor.engines.redis_.RedisDBHandle("example.com,6387,passwd,5", None)
        self.mredis.StrictRedis.assert_called_with(**expected)

    def test_init_defaults(self):
        expected = {
            "host": "localhost",
            "port": 6379,
            "password": None,
            "db": 0,
        }
        db = pyzor.engines.redis_.RedisDBHandle(",,,", None)
        self.mredis.StrictRedis.assert_called_with(**expected)

    def test_set(self):
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        value = "record test"

        db = pyzor.engines.redis_.RedisDBHandle(",,,", None)
        db[digest] = value

        expected = ("pyzord.digest_v1.%s" % digest, value)
        self.mredis.StrictRedis.return_value.hmset.assert_called_with(*expected)

    def test_set_max_age(self):
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        value = "record test"

        db = pyzor.engines.redis_.RedisDBHandle(",,,", None, max_age=self.max_age)
        db[digest] = value

        expected1 = ("pyzord.digest_v1.%s" % digest, value)
        expected2 = ("pyzord.digest_v1.%s" % digest, self.max_age)
        self.mredis.StrictRedis.return_value.hmset.assert_called_with(*expected1)
        self.mredis.StrictRedis.return_value.expire.assert_called_with(*expected2)

    def test_get(self):
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"

        db = pyzor.engines.redis_.RedisDBHandle(",,,", None)
        result = db[digest]

        expected = ("pyzord.digest_v1.%s" % digest,)
        self.mredis.StrictRedis.return_value.hgetall.assert_called_with(*expected)

    def test_items(self):
        patch(
            "pyzor.engines.redis_.redis.StrictRedis.return_value.keys",
            return_value=["2aedaac999d71421c9ee49b9d81f627a7bc570aa"],
        ).start()
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"

        db = pyzor.engines.redis_.RedisDBHandle(",,,", None)
        db.items()[0]

        expected = ("pyzord.digest_v1.%s" % digest,)
        self.mredis.StrictRedis.return_value.keys.assert_called_with(
            "pyzord.digest_v1.*"
        )
        self.mredis.StrictRedis.return_value.hgetall.assert_called_with(*expected)

    def test_delete(self):
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"

        db = pyzor.engines.redis_.RedisDBHandle(",,,", None)
        del db[digest]

        expected = ("pyzord.digest_v1.%s" % digest,)
        self.mredis.StrictRedis.return_value.delete.assert_called_with(*expected)


def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(EncodingRedisTest))
    test_suite.addTest(unittest.makeSuite(RedisTest))
    return test_suite


if __name__ == "__main__":
    unittest.main()
