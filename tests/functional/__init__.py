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
    import test_pyzor
    import test_server
    import test_digest
    import test_engines
    import test_account
    import test_forwarder

    test_suite = unittest.TestSuite()

    test_suite.addTest(test_pyzor.suite())
    test_suite.addTest(test_digest.suite())
    test_suite.addTest(test_server.suite())
    test_suite.addTest(test_engines.suite())
    test_suite.addTest(test_account.suite())
    test_suite.addTest(test_forwarder.suite())
    return test_suite


if __name__ == "__main__":
    unittest.main(defaultTest="suite")
