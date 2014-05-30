"""Test the pyzor.engines.mysql module."""

import unittest
import threading

from datetime import datetime, timedelta

import pyzor.engines
import pyzor.engines.mysql
import pyzor.engines.common

class MockTimer():
    def __init__(self, *args, **kwargs):
        pass
    def start(self):
        pass
    def setDaemon(self, daemon):
        pass

def make_MockMySQL(result, queries):
    class MockCursor():
        def __init__(self):
            pass

        def fetchone(self):
            return result
        def fetchall(self):
            return [result]
        def execute(self, query, args=None):
            queries.append((query, args))
        def close(self):
            pass
    class MockDB():
        def cursor(self):
            return MockCursor()
        def close(self):
            pass
        def commit(self):
            pass
        def autocommit(self, value):
            pass
    class MockMysql():
        @staticmethod
        def connect(*args, **kwargs):
            return MockDB()
        class Error(Exception):
            pass
    return MockMysql


class MySQLTest(unittest.TestCase):
    """Test the GdbmDBHandle class"""

    max_age = 60 * 60 * 24 * 30 * 4
    r_count = 24
    wl_count = 42
    entered = datetime.now() - timedelta(days=10)
    updated = datetime.now() - timedelta(days=2)
    wl_entered = datetime.now() - timedelta(days=20)
    wl_updated = datetime.now() - timedelta(days=3)

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.real_timer = threading.Timer
        threading.Timer = MockTimer

        self.record = pyzor.engines.common.Record(self.r_count, self.wl_count,
                                                  self.entered, self.updated,
                                                  self.wl_entered, self.wl_updated)

        self.response = self.record_unpack()
        self.queries = []

        mock_MySQL = make_MockMySQL(self.response, self.queries)
        self.real_mysql = pyzor.engines.mysql.MySQLdb
        pyzor.engines.mysql.MySQLdb = mock_MySQL


    def tearDown(self):
        unittest.TestCase.tearDown(self)
        threading.Timer = self.real_timer
        pyzor.engines.mysql.MySQLdb = self.real_mysql

    def record_unpack(self, record=None):
        if not record:
            record = self.record
        return (record.r_count, record.wl_count,
                record.r_entered, record.r_updated,
                record.wl_entered, record.wl_updated)

    def test_reconnect(self):
        """Test MySQLDBHandle.__init__"""
        expected = "DELETE FROM testtable WHERE r_updated<%s"

        pyzor.engines.mysql.MySQLDBHandle("testhost,testuser,testpass,testdb,testtable",
                                          None, max_age=self.max_age)

        self.assertEqual(self.queries[0][0], expected)

    def test_no_reorganize(self):
        pyzor.engines.mysql.MySQLDBHandle("testhost,testuser,testpass,testdb,testtable",
                                          None, max_age=None)
        self.assertFalse(self.queries)

    def test_set_item(self):
        """Test MySQLDBHandle.__setitem__"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        expected = ("INSERT INTO testtable (digest, r_count, wl_count, "
                    "r_entered, r_updated, wl_entered, wl_updated) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s) ON "
                    "DUPLICATE KEY UPDATE r_count=%s, wl_count=%s, "
                    "r_entered=%s, r_updated=%s, wl_entered=%s, "
                    "wl_updated=%s",
                    (digest, self.r_count, self.wl_count, self.entered,
                     self.updated, self.wl_entered, self.wl_updated,
                     self.r_count, self.wl_count, self.entered,
                     self.updated, self.wl_entered, self.wl_updated))
        handle = pyzor.engines.mysql.MySQLDBHandle("testhost,testuser,testpass,testdb,testtable",
                                                   None, max_age=self.max_age)

        handle[digest] = self.record
        self.assertEqual(self.queries[1], expected)

    def test_get_item(self):
        """Test MySQLDBHandle.__getitem__"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        expected = ("SELECT r_count, wl_count, r_entered, r_updated, "
                    "wl_entered, wl_updated FROM testtable WHERE digest=%s",
                    (digest,))
        handle = pyzor.engines.mysql.MySQLDBHandle("testhost,testuser,testpass,testdb,testtable",
                                                   None, max_age=self.max_age)

        result = handle[digest]
        self.assertEqual(self.queries[1], expected)
        self.assertEqual(self.record_unpack(result), self.record_unpack())

    def test_del_item(self):
        """Test MySQLDBHandle.__detitem__"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        expected = ("DELETE FROM testtable WHERE digest=%s", (digest,))

        handle = pyzor.engines.mysql.MySQLDBHandle("testhost,testuser,testpass,testdb,testtable",
                                                   None, max_age=self.max_age)
        del handle[digest]
        self.assertEqual(self.queries[1], expected)
        

def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(MySQLTest))
    return test_suite

if __name__ == '__main__':
    unittest.main()

