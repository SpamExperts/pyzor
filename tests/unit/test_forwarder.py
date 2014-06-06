"""Test the pyzor.forwarder module
"""
import time
import unittest
import threading

import pyzor.client
import pyzor.forwarder



class ForwarderTest(unittest.TestCase):

    def setUp(self):
        unittest.TestCase.setUp(self)

    def tearDown(self):
        unittest.TestCase.tearDown(self)

    def test_queue(self):
        client = pyzor.client.Client()
        servlist = []
        max_qsize = 10
        forwarder = pyzor.forwarder.Forwarder(client, servlist, max_queue_size=max_qsize)
        for _ in xrange(max_qsize * 2):
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
        self.assertFalse(t.isAlive(), 'forward thread did not end')

def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(ForwarderTest))
    return test_suite

if __name__ == '__main__':
    unittest.main()
