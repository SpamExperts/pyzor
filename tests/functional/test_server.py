import sys
import redis
import unittest

import pyzor.client

from tests.util import *

class BatchedDigestsTest(PyzorTestBase):
    password_file = None
    access = """ALL : anonymous : allow
"""
    servers = """127.0.0.1:9999
127.0.0.1:9998
"""

    def setUp(self):
        PyzorTestBase.setUp(self)
        self.client = pyzor.client.BatchClient()

    def check_digest(self, digest, address, counts=(0, 0)):
        result = self.client.check(digest, address)

        self.assertEqual((int(result["Count"]), int(result["WL-Count"])),
                          counts)
        return result

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



def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(BatchedDigestsTest))
    return test_suite

if __name__ == '__main__':
    unittest.main()
