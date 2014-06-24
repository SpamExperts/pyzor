"""Test the pyzor.engines.gdbm_ module."""

import unittest

from datetime import datetime, timedelta

import pyzor.engines
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

        self.record = pyzor.engines.common.Record(self.r_count, self.wl_count,
                                                  self.entered, self.updated,
                                                  self.wl_entered, self.wl_updated)

    def compare_records(self, r1, r2):
        attrs = ("r_count", "r_entered", "r_updated",
                 "wl_count", "wl_entered", "wl_updated")
        self.assertTrue(all(getattr(r1, attr) == getattr(r2, attr)
                            for attr in attrs))

    def tearDown(self):
        unittest.TestCase.tearDown(self)

    def test_encode_record(self):
        expected = ("24,2014-04-23 15:41:30,2014-04-25 17:22:25,"
                    "42,2014-02-12 11:10:55,2014-03-25 05:01:50").encode()
        result = pyzor.engines.redis_.RedisDBHandle._encode_record(self.record)
        self.assertEqual(result, expected)

    def test_encode_record_no_date(self):
        expected = ("24,2014-04-23 15:41:30,,"
                    "42,2014-02-12 11:10:55,2014-03-25 05:01:50").encode()
        self.record.r_updated = None
        result = pyzor.engines.redis_.RedisDBHandle._encode_record(self.record)
        self.assertEqual(result, expected)

    def test_encode_record_no_white(self):
        expected = ("24,2014-04-23 15:41:30,2014-04-25 17:22:25,"
                    "0,,").encode()
        self.record.wl_count = 0
        self.record.wl_entered = None
        self.record.wl_updated = None
        result = pyzor.engines.redis_.RedisDBHandle._encode_record(self.record)
        self.assertEqual(result, expected)

    def test_decode_record(self):
        encoded = ("24,2014-04-23 15:41:30,2014-04-25 17:22:25,"
                   "42,2014-02-12 11:10:55,2014-03-25 05:01:50").encode()
        result = pyzor.engines.redis_.RedisDBHandle._decode_record(encoded)
        self.compare_records(result, self.record)

    def test_decode_record_no_date(self):
        encoded = ("24,2014-04-23 15:41:30,,"
                   "42,2014-02-12 11:10:55,2014-03-25 05:01:50").encode()
        result = pyzor.engines.redis_.RedisDBHandle._decode_record(encoded)
        self.record.r_updated = None
        self.compare_records(result, self.record)

    def test_decode_record_no_white(self):
        encoded = ("24,2014-04-23 15:41:30,2014-04-25 17:22:25,"
                   "0,,").encode()
        result = pyzor.engines.redis_.RedisDBHandle._decode_record(encoded)
        self.record.wl_count = 0
        self.record.wl_entered = None
        self.record.wl_updated = None
        self.compare_records(result, self.record)

def make_MockRedis(commands):
    class MockStrictRedis():
        def __init__(self, *args, **kwargs):
            commands.append(("init", args, kwargs))
        def set(self, *args, **kwargs):
            commands.append(("set", args, kwargs))
        def setex(self, *args, **kwargs):
            commands.append(("setex", args, kwargs))
        def get(self, *args, **kwargs):
            commands.append(("get", args, kwargs))
        def delete(self, *args, **kwargs):
            commands.append(("delete", args, kwargs))
    class MockError(Exception):
        pass
    class exceptions():
        def __init__(self):
            self.RedisError = MockError 
    class MockRedis():
        def __init__(self):
            self.StrictRedis = MockStrictRedis
            self.exceptions = exceptions()
    return MockRedis()

mock_encode_record = lambda s, x: x
mock_decode_record = lambda s, x: x

class RedisTest(unittest.TestCase):

    max_age = 60 * 60

    def setUp(self):
        unittest.TestCase.setUp(self)

        self.commands = []

        try:
            self.real_redis = pyzor.engines.redis_.redis
        except AttributeError:
            self.real_redis = None
        self.real_encode = pyzor.engines.redis_.RedisDBHandle._encode_record
        self.real_decode = pyzor.engines.redis_.RedisDBHandle._decode_record

        setattr(pyzor.engines.redis_, "redis", make_MockRedis(self.commands))
        pyzor.engines.redis_.RedisDBHandle._encode_record = mock_encode_record
        pyzor.engines.redis_.RedisDBHandle._decode_record = mock_decode_record

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        pyzor.engines.redis_.redis = self.real_redis
        pyzor.engines.redis_.RedisDBHandle._encode_record = self.real_encode
        pyzor.engines.redis_.RedisDBHandle._decode_record = self.real_decode

    def test_init(self):
        expected = {"host": "example.com",
                    "port": 6387,
                    "password": "passwd",
                    "db": 5,
                    }
        db = pyzor.engines.redis_.RedisDBHandle("example.com,6387,passwd,5",
                                                None)
        self.assertEqual(self.commands[0], ("init", (), expected))
        
    def test_init_defaults(self):
        expected = {"host": "localhost",
                    "port": 6379,
                    "password": None,
                    "db": 0,
                    }
        db = pyzor.engines.redis_.RedisDBHandle(",,,", None)
        self.assertEqual(self.commands[0], ("init", (), expected))
        
    def test_set(self):
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        value = "record test"

        db = pyzor.engines.redis_.RedisDBHandle(",,,", None)
        db[digest] = value
        
        expected = ("pyzord.digest.%s" % digest, value)
        self.assertEqual(self.commands[1], ("set", expected, {}))

    def test_set_max_age(self):
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        value = "record test"

        db = pyzor.engines.redis_.RedisDBHandle(",,,", None,
                                                max_age=self.max_age)
        db[digest] = value

        expected = ("pyzord.digest.%s" % digest, self.max_age, value)
        self.assertEqual(self.commands[1], ("setex", expected, {}))

    def test_get(self):
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"

        db = pyzor.engines.redis_.RedisDBHandle(",,,", None)
        result = db[digest]

        expected = ("pyzord.digest.%s" % digest,)
        self.assertEqual(self.commands[1], ("get", expected, {}))

    def test_delete(self):
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"

        db = pyzor.engines.redis_.RedisDBHandle(",,,", None)
        del db[digest]

        expected = ("pyzord.digest.%s" % digest,)
        self.assertEqual(self.commands[1], ("delete", expected, {}))

def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(EncodingRedisTest))
    test_suite.addTest(unittest.makeSuite(RedisTest))
    return test_suite

if __name__ == '__main__':
    unittest.main()
