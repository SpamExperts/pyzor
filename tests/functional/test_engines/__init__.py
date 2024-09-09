"""A suite of functional tests that verifies the correct behaviour of the
pyzor client and server as a whole.

Functional test should not touch real data and are usually safe, but it's not
recommended to run theses on production servers.

Note these tests the installed version of pyzor, not the version from the
source.
"""

import unittest


def suite():
    """Gather all the tests from this package in a test suite."""
    from . import test_gdbm
    from . import test_mysql
    from . import test_redis

    test_suite = unittest.TestSuite()

    test_suite.addTest(test_gdbm.suite())
    test_suite.addTest(test_mysql.suite())
    test_suite.addTest(test_redis.suite())
    return test_suite


if __name__ == "__main__":
    unittest.main(defaultTest="suite")
