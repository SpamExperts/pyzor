"""Test the pyzor.server_engines module
"""
import sys
import time
import gdbm
import unittest
import threading

from datetime import datetime, timedelta

import pyzor.server_engines

class MockTimer():
    def __init__(self, *args, **kwargs):
        pass
    def start(self):
        pass
    
class MockGdbm(dict):
    """Mock a gdbm database"""
    
    def firstkey(self):
        if not self.keys():
            return None
        self.key_index = 1
        return self.keys()[0]
    
    def nextkey(self, key):
        if len(self.keys()) <= self.key_index:
            return None
        else:
            self.key_index += 1
            return self.keys()[self.key_index]
    
    def sync(self):
        pass
    def reorganize(self):
        pass
    
class GdbmTest(unittest.TestCase):            
    """Test the GdbmDBHandle class"""
    
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.real_timer = threading.Timer
        threading.Timer = MockTimer
        
        self.db = MockGdbm()
        def mock_open(fn, mode):
            return self.db
        self.real_open = gdbm.open
        gdbm.open = mock_open        
        
        self.r_count = 24
        self.wl_count = 42
        self.entered = datetime.now() - timedelta(days=10)
        self.updated = datetime.now() - timedelta(days=2)
        self.wl_entered = datetime.now() - timedelta(days=20)
        self.wl_updated = datetime.now() - timedelta(days=3)
        self.record = pyzor.server_engines.Record(self.r_count, self.wl_count,
                                                  self.entered, self.updated,
                                                  self.wl_entered, self.wl_updated)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        threading.Timer = self.real_timer
        gdbm.open = self.real_open 
    
    def record_as_str(self, record=None):
        if not record:
            record = self.record
        return ("1,%s,%s,%s,%s,%s,%s" % (record.r_count, record.r_entered,
                                        record.r_updated, record.wl_count,
                                        record.wl_entered, record.wl_updated)).encode("utf8")
    
    def test_set_item(self):
        """Test GdbmDBHandle.__setitem__"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"        

        handle = pyzor.server_engines.GdbmDBHandle(None, None)
        handle[digest] = self.record
        
        self.assertEqual(self.db[digest], self.record_as_str().decode("utf8"))        

    def test_get_item(self):
        """Test GdbmDBHandle.__getitem__"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"        
                
        handle = pyzor.server_engines.GdbmDBHandle(None, None)
        self.db[digest] = self.record_as_str()
        
        result = handle[digest]
        
        self.assertEqual(self.record_as_str(result), self.record_as_str())
        
    def test_del_item(self):
        """Test GdbmDBHandle.__delitem__"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        handle = pyzor.server_engines.GdbmDBHandle(None, None)
        self.db[digest] = self.record_as_str()
        
        del handle[digest]
        
        self.assertFalse(self.db.get(digest))
        
    def test_reorganize_older(self):
        """Test GdbmDBHandle.start_reorganizing with older records"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        
        self.db[digest] = self.record_as_str()
        handle = pyzor.server_engines.GdbmDBHandle(None, None, 3600 * 24)
        
        self.assertFalse(self.db.get(digest))
    
    def test_reorganize_fresh(self):
        """Test GdbmDBHandle.start_reorganizing with newer records"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        
        self.db[digest] = self.record_as_str()
        handle = pyzor.server_engines.GdbmDBHandle(None, None, 3600 * 24 * 3)
        
        self.assertEqual(self.db[digest], self.record_as_str())

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
    
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.real_timer = threading.Timer
        threading.Timer = MockTimer            
        
        self.r_count = 24
        self.wl_count = 42
        self.entered = datetime.now() - timedelta(days=10)
        self.updated = datetime.now() - timedelta(days=2)
        self.wl_entered = datetime.now() - timedelta(days=20)
        self.wl_updated = datetime.now() - timedelta(days=3)
        self.record = pyzor.server_engines.Record(self.r_count, self.wl_count,
                                                  self.entered, self.updated,
                                                  self.wl_entered, self.wl_updated)

        self.response = self.record_unpack()
        self.queries = []
        
        mock_MySQL = make_MockMySQL(self.response, self.queries)
        self.real_mysql = pyzor.server_engines.MySQLdb
        pyzor.server_engines.MySQLdb = mock_MySQL


    def tearDown(self):
        unittest.TestCase.tearDown(self)
        threading.Timer = self.real_timer
        pyzor.server_engines.MySQLdb = self.real_mysql
    
    def record_unpack(self, record=None):
        if not record:
            record = self.record
        return (record.r_count, record.wl_count,
                record.r_entered, record.r_updated,
                record.wl_entered, record.wl_updated)
        
    def test_reconnect(self):
        """Test MySQLDBHandle.__init__"""
        expected = "DELETE FROM testtable WHERE r_updated<%s"
        pyzor.server_engines.MySQLDBHandle("testhost,testuser,testpass,testdb,testtable", None)
        
        self.assertEqual(self.queries[0][0], expected)
        
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
        handle = pyzor.server_engines.MySQLDBHandle("testhost,testuser,testpass,testdb,testtable", None)
        
        handle[digest] = self.record        
        self.assertEqual(self.queries[1], expected)
    
    def test_get_item(self):
        """Test MySQLDBHandle.__getitem__"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        expected = ("SELECT r_count, wl_count, r_entered, r_updated, "
                    "wl_entered, wl_updated FROM testtable WHERE digest=%s",
                    (digest,))
        handle = pyzor.server_engines.MySQLDBHandle("testhost,testuser,testpass,testdb,testtable", None)
        
        result = handle[digest]        
        self.assertEqual(self.queries[1], expected)
        self.assertEqual(self.record_unpack(result), self.record_unpack())
    
    def test_del_item(self):
        """Test MySQLDBHandle.__detitem__"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        expected = ("DELETE FROM testtable WHERE digest=%s", (digest,))
                
        handle = pyzor.server_engines.MySQLDBHandle("testhost,testuser,testpass,testdb,testtable", None)
        del handle[digest]
        self.assertEqual(self.queries[1], expected)
        
def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(GdbmTest))
    test_suite.addTest(unittest.makeSuite(MySQLTest))    
    return test_suite
        
if __name__ == '__main__':
    unittest.main()

