"""A suite of unit tests that verifies the correct behaviour of various
functions/methods in the pyzord code.

Note these tests the source of pyzor, not the version currently installed.
"""

import unittest


def suite():
    """Gather all the tests from this package in a test suite."""
    from . import test_gdbm
    from . import test_mysql
    from . import test_redis
    from . import test_redis_v0

    test_suite = unittest.TestSuite()

    test_suite.addTest(test_gdbm.suite())
    test_suite.addTest(test_mysql.suite())
    test_suite.addTest(test_redis.suite())
    test_suite.addTest(test_redis_v0.suite())
    return test_suite


if __name__ == "__main__":
    unittest.main(defaultTest="suite")
