"""A suite of unit tests that verifies the correct behaviour of various 
functions/methods in the pyzord code.

Note these tests the source of pyzor, not the version currently installed.
"""

import unittest

import test_gdbm
import test_mysql
import test_redis
import test_client
import test_digest
import test_server
import test_account

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()

    test_suite.addTest(test_gdbm.suite())
    test_suite.addTest(test_mysql.suite())
    test_suite.addTest(test_redis.suite())
    test_suite.addTest(test_client.suite())
    test_suite.addTest(test_digest.suite())
    test_suite.addTest(test_server.suite())
    test_suite.addTest(test_account.suite())
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')

