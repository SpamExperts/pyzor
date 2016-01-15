"""Test the pyzor.engines.gdbm_ module."""

import sys
import time
import unittest
import threading

from datetime import datetime, timedelta

import pyzor.engines.gdbm_
import pyzor.engines.common

class MockTimer():
    def __init__(self, *args, **kwargs):
        pass
    def start(self):
        pass
    def setDaemon(self, daemon):
        pass

class MockGdbmDB(dict):
    """Mock a gdbm database"""

    def firstkey(self):
        if not self.keys():
            return None
        self.key_index = 1
        return list(self.keys())[0]

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

    handler = pyzor.engines.gdbm_.GdbmDBHandle

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

        self.db = MockGdbmDB()
        class MockGdbm():
            @staticmethod
            def open(fn, mode):
                return self.db

        try:
            self.real_gdbm = pyzor.engines.gdbm_.gdbm
        except AttributeError:
            self.real_gdbm = None
        setattr(pyzor.engines.gdbm_, "gdbm", MockGdbm())

        self.record = pyzor.engines.common.Record(self.r_count, self.wl_count,
                                                  self.entered, self.updated,
                                                  self.wl_entered, self.wl_updated)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        threading.Timer = self.real_timer
        pyzor.engines.gdbm_.gdbm = self.real_gdbm

    def record_as_str(self, record=None):
        if not record:
            record = self.record
        return ("1,%s,%s,%s,%s,%s,%s" % (record.r_count, record.r_entered,
                                         record.r_updated, record.wl_count,
                                         record.wl_entered, record.wl_updated)).encode("utf8")

    def test_set_item(self):
        """Test GdbmDBHandle.__setitem__"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"

        handle = self.handler(None, None, max_age=self.max_age)
        handle[digest] = self.record

        self.assertEqual(self.db[digest], self.record_as_str().decode("utf8"))

    def test_get_item(self):
        """Test GdbmDBHandle.__getitem__"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"

        handle = self.handler(None, None, max_age=self.max_age)
        self.db[digest] = self.record_as_str()

        result = handle[digest]

        self.assertEqual(self.record_as_str(result), self.record_as_str())

    def test_items(self):
        """Test GdbmDBHandle.items()"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"

        handle = self.handler(None, None, max_age=self.max_age)
        self.db[digest] = self.record_as_str()
        key, result = handle.items()[0]

        self.assertEqual(key, digest)
        self.assertEqual(self.record_as_str(result), self.record_as_str())

    def test_del_item(self):
        """Test GdbmDBHandle.__delitem__"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        handle = self.handler(None, None, max_age=self.max_age)
        self.db[digest] = self.record_as_str()

        del handle[digest]

        self.assertFalse(self.db.get(digest))

    def test_reorganize_older(self):
        """Test GdbmDBHandle.start_reorganizing with older records"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"

        self.db[digest] = self.record_as_str()
        handle = self.handler(None, None, max_age=3600 * 24)

        self.assertFalse(self.db.get(digest))

    def test_reorganize_older_no_max_age(self):
        """Test GdbmDBHandle.start_reorganizing with older records, but no
        max_age set.
        """
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"

        self.db[digest] = self.record_as_str()
        handle = self.handler(None, None, max_age=None)

        self.assertEqual(self.db[digest], self.record_as_str())

    def test_reorganize_fresh(self):
        """Test GdbmDBHandle.start_reorganizing with newer records"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"

        self.db[digest] = self.record_as_str()
        handle = self.handler(None, None, max_age=3600 * 24 * 3)

        self.assertEqual(self.db[digest], self.record_as_str())

class ThreadingGdbmTest(GdbmTest):
    """Test the GdbmDBHandle class"""
    handler = pyzor.engines.gdbm_.ThreadedGdbmDBHandle


def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(GdbmTest))
    test_suite.addTest(unittest.makeSuite(ThreadingGdbmTest))
    return test_suite

if __name__ == '__main__':
    unittest.main()
