"""Package reserved for tests and test utilities."""

import unittest


def suite():
    """Gather all the tests from this package in a test suite."""
    import tests.unit as unit
    import tests.functional as functional

    test_suite = unittest.TestSuite()

    test_suite.addTest(unit.suite())
    test_suite.addTest(functional.suite())

    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
