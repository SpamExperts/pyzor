import unittest

from tests.util import *

try:
    import gdbm

    has_gdbm = True
except ImportError:
    has_gdbm = False


@unittest.skipIf(not has_gdbm, "gdbm library not available")
class GdbmPyzorTest(PyzorTest, PyzorTestBase):
    """Test the gdbm engine"""

    dsn = "pyzord.db"
    engine = "gdbm"


class ThreadsGdbmPyzorTest(GdbmPyzorTest):
    """Test the gdbm engine with threads activated."""

    threads = "True"
    max_threads = "0"


class MaxThreadsGdbmPyzorTest(GdbmPyzorTest):
    """Test the gdbm engine with with maximum threads."""

    threads = "True"
    max_threads = "10"


def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(GdbmPyzorTest))
    test_suite.addTest(unittest.makeSuite(ThreadsGdbmPyzorTest))
    test_suite.addTest(unittest.makeSuite(MaxThreadsGdbmPyzorTest))
    return test_suite


if __name__ == "__main__":
    unittest.main()
