import sys
import unittest
import ConfigParser

import pyzor.client

from tests.util import *

try:
    import MySQLdb
    has_mysql = True
except ImportError:
    has_mysql = False

try:
    import redis
    has_redis = True
except ImportError:
    has_redis = False

try:
    import gdbm
    has_gdbm = True
except ImportError:
    has_gdbm = False


class BatchedDigestsTest(object):

    def setUp(self):
        PyzorTestBase.setUp(self)
        self.client = pyzor.client.BatchClient()

    def test_batched_report(self):
        digest = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

        for i in range(9):
            self.client.report(digest, ("127.0.0.1", 9999))
        self.check_digest(digest, ("127.0.0.1", 9999))

        self.client.report(digest, ("127.0.0.1", 9999))
        self.check_digest(digest, ("127.0.0.1", 9999), (10, 0))

    def test_batched_whitelist(self):
        digest = "da39a3ee5e6b4b0d3255bfef95601890afd80708"

        for i in range(9):
            self.client.whitelist(digest, ("127.0.0.1", 9999))
        self.check_digest(digest, ("127.0.0.1", 9999))

        self.client.whitelist(digest, ("127.0.0.1", 9999))
        self.check_digest(digest, ("127.0.0.1", 9999), (0, 10))

    def test_batched_combined(self):
        digest = "da39a3ee5e6b4b0d3255bfef95601890afd80707"

        for i in range(9):
            self.client.report(digest, ("127.0.0.1", 9999))
            self.client.whitelist(digest, ("127.0.0.1", 9999))
        self.check_digest(digest, ("127.0.0.1", 9999))

        self.client.report(digest, ("127.0.0.1", 9999))
        self.check_digest(digest, ("127.0.0.1", 9999), (10, 0))

        self.client.whitelist(digest, ("127.0.0.1", 9999))
        self.check_digest(digest, ("127.0.0.1", 9999), (10, 10))

    def test_batched_multiple_report(self):
        digest = "%sa39a3ee5e6b4b0d3255bfef95601890afd80706"
        for i in range(10):
            self.client.report(digest % i, ("127.0.0.1", 9999))

        for i in range(10):
            self.check_digest(digest % i, ("127.0.0.1", 9999), (1, 0))

    def test_batched_multiple_whitelist(self):
        digest = "%sa39a3ee5e6b4b0d3255bfef95601890afd80705"
        for i in range(10):
            self.client.whitelist(digest % i, ("127.0.0.1", 9999))

        for i in range(10):
            self.check_digest(digest % i, ("127.0.0.1", 9999), (0, 1))

    def test_multiple_addresses_report(self):
        digest1 = "da39a3ee5e6b4b0d3255bfef95601890afd80704"
        digest2 = "da39a3ee5e6b4b0d3255bfef95601890afd80703"
        for i in range(9):
            self.client.report(digest1, ("127.0.0.1", 9999))
            self.client.report(digest2, ("127.0.0.1", 9998))

        self.check_digest(digest1, ("127.0.0.1", 9999))
        self.check_digest(digest2, ("127.0.0.1", 9998))

        self.client.report(digest1, ("127.0.0.1", 9999))
        self.check_digest(digest1, ("127.0.0.1", 9999), (10, 0))

        self.client.report(digest2, ("127.0.0.1", 9998))
        self.check_digest(digest2, ("127.0.0.1", 9998), (10, 0))

    def test_multiple_addresses_whitelist(self):
        digest1 = "da39a3ee5e6b4b0d3255bfef95601890afd80702"
        digest2 = "da39a3ee5e6b4b0d3255bfef95601890afd80701"
        for i in range(9):
            self.client.whitelist(digest1, ("127.0.0.1", 9999))
            self.client.whitelist(digest2, ("127.0.0.1", 9998))

        self.check_digest(digest1, ("127.0.0.1", 9999))
        self.check_digest(digest2, ("127.0.0.1", 9998))

        self.client.whitelist(digest1, ("127.0.0.1", 9999))
        self.check_digest(digest1, ("127.0.0.1", 9999), (0, 10))

        self.client.whitelist(digest2, ("127.0.0.1", 9998))
        self.check_digest(digest2, ("127.0.0.1", 9998), (0, 10))


schema = """
    CREATE TABLE IF NOT EXISTS `%s` (
    `digest` char(40) default NULL,
    `r_count` int(11) default NULL,
    `wl_count` int(11) default NULL,
    `r_entered` datetime default NULL,
    `wl_entered` datetime default NULL,
    `r_updated` datetime default NULL,
    `wl_updated` datetime default NULL,
    PRIMARY KEY  (`digest`)
    )
"""


@unittest.skipIf(not os.path.exists("./test.conf"),
                 "test.conf is not available")
@unittest.skipIf(not has_mysql, "MySQLdb library not available")
class MySQLdbBatchedPyzorTest(BatchedDigestsTest, PyzorTestBase):
    """Test the mysql engine."""
    dsn = None
    engine = "mysql"
    password_file = None
    access = """ALL : anonymous : allow
"""
    servers = """127.0.0.1:9999
127.0.0.1:9998
"""

    @classmethod
    def setUpClass(cls):
        conf = ConfigParser.ConfigParser()
        conf.read("./test.conf")
        table = conf.get("test", "table")
        db = MySQLdb.Connect(host=conf.get("test", "host"),
                             user=conf.get("test", "user"),
                             passwd=conf.get("test", "passwd"),
                             db=conf.get("test", "db"))
        c = db.cursor()
        c.execute(schema % table)
        c.close()
        db.close()
        cls.dsn = "%s,%s,%s,%s,%s" % (conf.get("test", "host"),
                                      conf.get("test", "user"),
                                      conf.get("test", "passwd"),
                                      conf.get("test", "db"),
                                      conf.get("test", "table"))
        super(MySQLdbBatchedPyzorTest, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(MySQLdbBatchedPyzorTest, cls).tearDownClass()
        try:
            conf = ConfigParser.ConfigParser()
            conf.read("./test.conf")
            table = conf.get("test", "table")
            db = MySQLdb.Connect(host=conf.get("test", "host"),
                                 user=conf.get("test", "user"),
                                 passwd=conf.get("test", "passwd"),
                                 db=conf.get("test", "db"))
            c = db.cursor()
            c.execute("DROP TABLE %s" % table)
            c.close()
            db.close()
        except:
            pass


@unittest.skipIf(not has_redis, "redis library not available")
class RedisBatchedPyzorTest(BatchedDigestsTest, PyzorTestBase):
    """Test the redis engine"""
    dsn = "localhost,,,10"
    engine = "redis"
    password_file = None
    access = """ALL : anonymous : allow
"""
    servers = """127.0.0.1:9999
127.0.0.1:9998
"""

    @classmethod
    def tearDownClass(cls):
        super(RedisBatchedPyzorTest, cls).tearDownClass()
        redis.StrictRedis(db=10).flushdb()


def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(MySQLdbBatchedPyzorTest))
    # test_suite.addTest(unittest.makeSuite(GdbmBatchedPyzorTest))
    test_suite.addTest(unittest.makeSuite(RedisBatchedPyzorTest))
    return test_suite

if __name__ == '__main__':
    unittest.main()
