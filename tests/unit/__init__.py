"""A suite of unit tests that verifies the correct behaviour of various 
functions/methods in the pyzord code.

Note these tests the source of pyzor, not the version currently installed.
"""

import unittest


def suite():
    """Gather all the tests from this package in a test suite."""
    import test_client
    import test_config
    import test_digest
    import test_server
    import test_account
    import test_forwarder
    import test_engines

    test_suite = unittest.TestSuite()

    test_suite.addTest(test_engines.suite())
    test_suite.addTest(test_client.suite())
    test_suite.addTest(test_config.suite())
    test_suite.addTest(test_digest.suite())
    test_suite.addTest(test_server.suite())
    test_suite.addTest(test_account.suite())
    test_suite.addTest(test_forwarder.suite())
    return test_suite


if __name__ == "__main__":
    unittest.main(defaultTest="suite")
