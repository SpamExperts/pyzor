import unittest

import test_gdbm
import test_mysql
import test_client
import test_digest
import test_server
import test_account

import test_gdbm_functional
import test_pyzor_functional
import test_mysql_functional
import test_redis_functional
import test_digest_functional
import test_account_functional

def suite():
    """Gather all the tests from this module in a test suite."""    
    test_suite = unittest.TestSuite()
    test_suite.addTest(test_gdbm.suite())
    test_suite.addTest(test_mysql.suite())
    test_suite.addTest(test_client.suite())
    test_suite.addTest(test_digest.suite())
    test_suite.addTest(test_server.suite())
    test_suite.addTest(test_account.suite())
    test_suite.addTest(test_gdbm_functional.suite())
    test_suite.addTest(test_mysql_functional.suite())
    test_suite.addTest(test_redis_functional.suite())
    test_suite.addTest(test_pyzor_functional.suite())
    test_suite.addTest(test_digest_functional.suite())
    test_suite.addTest(test_account_functional.suite())
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
