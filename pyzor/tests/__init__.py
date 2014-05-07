"""Package reserved for tests and test utilities."""

import unittest

import unit
import functional

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()

    test_suite.addTest(unit.suite())
    test_suite.addTest(functional.suite())

    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
