import unittest

try:
    import redis

    has_redis = True
except ImportError:
    has_redis = False

from tests.util import *


@unittest.skipIf(not has_redis, "redis library not available")
class RedisPyzorTest(PyzorTest, PyzorTestBase):
    """Test the redis engine"""

    dsn = "localhost,,,10"
    engine = "redis"

    @classmethod
    def tearDownClass(cls):
        super(RedisPyzorTest, cls).tearDownClass()
        redis.StrictRedis(db=10).flushdb()


class ThreadsRedisPyzorTest(RedisPyzorTest):
    """Test the redis engine with threads activated."""

    threads = "True"


class MaxThreadsRedisPyzorTest(RedisPyzorTest):
    """Test the gdbm engine with with maximum threads."""

    threads = "True"
    max_threads = "10"


class PreForkRedisPyzorTest(RedisPyzorTest):
    """Test the redis engine with threads activated."""

    prefork = "4"


def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(RedisPyzorTest))
    test_suite.addTest(unittest.makeSuite(ThreadsRedisPyzorTest))
    test_suite.addTest(unittest.makeSuite(MaxThreadsRedisPyzorTest))
    test_suite.addTest(unittest.makeSuite(PreForkRedisPyzorTest))
    return test_suite


if __name__ == "__main__":
    unittest.main()
