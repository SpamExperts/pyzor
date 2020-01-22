"""Test the pyzor.forwarder module
"""
import time
import unittest
import threading

try:
    from unittest.mock import call, Mock
except ImportError:
    from mock import call, Mock

import pyzor.forwarder


class ForwarderTest(unittest.TestCase):

    def setUp(self):
        unittest.TestCase.setUp(self)

    def tearDown(self):
        unittest.TestCase.tearDown(self)

    def test_queue(self):
        client = Mock()
        servlist = []
        max_qsize = 10
        forwarder = pyzor.forwarder.Forwarder(client, servlist,
                                              max_queue_size=max_qsize)
        for _ in range(max_qsize * 2):
            forwarder.queue_forward_request('975422c090e7a43ab7c9bf0065d5b661259e6d74')
            self.assertGreater(forwarder.forward_queue.qsize(), 0, 'queue insert failed')
            self.assertLessEqual(forwarder.forward_queue.qsize(), max_qsize, 'queue overload')
        self.assertEqual(forwarder.forward_queue.qsize(), max_qsize, 'queue should be full at this point')
        t = threading.Thread(target=forwarder._forward_loop)
        t.start()
        time.sleep(1)
        self.assertEqual(forwarder.forward_queue.qsize(), 0, 'queue should be empty')
        forwarder.stop_forwarding()
        t.join(5)
        self.assertFalse(t.is_alive(), 'forward thread did not end')

    def test_remote_servers(self):
        client = Mock()
        digest = '975422c090e7a43ab7c9bf0065d5b661259e6d74'
        servlist = [("test1.example.com", 24441),
                    ("test2.example.com", 24442)]
        forwarder = pyzor.forwarder.Forwarder(client, servlist)

        forwarder.queue_forward_request(digest)
        forwarder.queue_forward_request(digest, whitelist=True)

        forwarder.start_forwarding()
        time.sleep(2)
        forwarder.stop_forwarding()

        client.report.assert_has_calls([call(digest, servlist[0]),
                                        call(digest, servlist[1])])
        client.whitelist.assert_has_calls([call(digest, servlist[0]),
                                           call(digest, servlist[1])])


def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(ForwarderTest))
    return test_suite

if __name__ == '__main__':
    unittest.main()
