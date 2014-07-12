import time
import email
import unittest

from mock import Mock, patch, call

import pyzor.client
import pyzor.account


class TestBase(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)

        self.thread = 33715

        patch("pyzor.account.sign_msg", return_value="TestSig").start()
        patch("pyzor.account.hash_key").start()

        # the response the mock socket will send
        self.response = {"Code": "200",
                         "Diag": "OK",
                         "PV": "2.1",
                         "Thread": "33715"
        }
        self.mresponse = None
        self.mock_socket = None

        # the expected request that the client should send
        self.expected = {"Thread": str(self.thread),
                         "PV": str(pyzor.proto_version),
                         "User": "anonymous",
                         "Time": str(int(time.time())),
                         "Sig": "TestSig"
        }

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def get_requests(self):
        for mock_call in self.mock_socket.mock_calls:
            name, args, kwargs = mock_call
            if name == "socket().sendto":
                yield args, kwargs

    def check_request(self):
        """Check if the request sent by the client is equal
        to the expected one.
        """
        req = {}
        for args, _ in self.get_requests():
            self.assertEqual(args[2], ('127.0.0.1', 24441))
            req = dict(email.message_from_string(args[0].decode()))
        self.assertEqual(req, self.expected)

    def patch_all(self, conf=None):
        if conf is None:
            conf = {}

        patch("pyzor.message.ThreadId.generate",
              return_value=self.thread).start()

        if self.response:
            response = "\n".join("%s: %s" % (key, value)
                                 for key, value in self.response.items()) + "\n\n"
            self.mresponse = response.encode(), ("127.0.0.1", 24441)
        else:
            self.mresponse = None
        addrinfo = [(2, 2, 17, '', ('127.0.0.1', 24441))]

        config = {"socket.return_value": Mock(),
                  "socket.return_value.recvfrom.return_value": self.mresponse,
                  "getaddrinfo.return_value": addrinfo}
        config.update(conf)

        self.mock_socket = patch("pyzor.client.socket", **config).start()

    def check_client(self, accounts, method, *args, **kwargs):
        """Tests if the request and response are sent
        and read correctly by the client.
        """
        client = pyzor.client.Client(accounts)
        got_response = getattr(client, method)(*args, **kwargs)

        self.assertEqual(str(got_response), self.mresponse[0])
        if self.expected is not None:
            self.check_request()
        return client


class ClientTest(TestBase):
    def test_ping(self):
        """Test the client ping request"""
        self.expected["Op"] = "ping"
        self.patch_all()
        self.check_client(None, "ping")

    def test_pong(self):
        """Test the client pong request"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.expected["Op"] = "pong"
        self.expected["Op-Digest"] = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.patch_all()
        self.check_client(None, "pong", digest)

    def test_check(self):
        """Test the client check request"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.expected["Op"] = "check"
        self.expected["Op-Digest"] = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.patch_all()
        self.check_client(None, "check", digest)

    def test_info(self):
        """Test the client info request"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.expected["Op"] = "info"
        self.expected["Op-Digest"] = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.patch_all()
        self.check_client(None, "info", digest)

    def test_report(self):
        """Test the client report request"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.expected["Op"] = "report"
        self.expected["Op-Digest"] = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.expected["Op-Spec"] = "20,3,60,3"
        self.patch_all()
        self.check_client(None, "report", digest)

    def test_whitelist(self):
        """Test the client whitelist request"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.expected["Op"] = "whitelist"
        self.expected["Op-Digest"] = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.expected["Op-Spec"] = "20,3,60,3"
        self.patch_all()
        self.check_client(None, "whitelist", digest)

    def test_handle_account(self):
        """Test client handling accounts"""
        test_account = pyzor.account.Account("TestUser", "TestKey", "TestSalt")
        self.expected["Op"] = "ping"
        self.expected["User"] = "TestUser"
        self.patch_all()
        self.check_client({("public.pyzor.org", 24441): test_account}, "ping")

    def test_handle_invalid_thread(self):
        """Test invalid thread id"""
        self.thread += 20
        self.expected["Op"] = "ping"
        self.patch_all()
        self.assertRaises(pyzor.ProtocolError, self.check_client, None, "ping")

    def test_set_timeout(self):
        self.expected = None
        self.patch_all()
        self.check_client(None, "ping")

        calls = [call('socket().settimeout', (10,), {}), ]
        self.mock_socket.has_calls(calls)


class BatchClientTest(TestBase):
    def test_report(self):
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.patch_all()

        client = pyzor.client.BatchClient()
        for i in range(10):
            client.report(digest)

        args, kwargs = list(self.get_requests())[0]

        msg = email.message_from_string(args[0])
        self.assertEqual(len(msg.get_all("Op-Digest")), 10)

    def test_report_to_few(self):
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.patch_all()

        client = pyzor.client.BatchClient()
        for i in range(9):
            client.report(digest)

        self.assertEqual(list(self.get_requests()), [])

    def test_whitelist(self):
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.patch_all()

        client = pyzor.client.BatchClient()
        for i in range(10):
            client.whitelist(digest)

        args, kwargs = list(self.get_requests())[0]

        msg = email.message_from_string(args[0])
        self.assertEqual(len(msg.get_all("Op-Digest")), 10)

    def test_whitelist_to_few(self):
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.patch_all()

        client = pyzor.client.BatchClient()
        for i in range(9):
            client.whitelist(digest)

        self.assertEqual(list(self.get_requests()), [])

    def test_force_report(self):
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.patch_all()

        client = pyzor.client.BatchClient()
        for i in range(9):
            client.report(digest)
        client.force()
        args, kwargs = list(self.get_requests())[0]

        msg = email.message_from_string(args[0])
        self.assertEqual(len(msg.get_all("Op-Digest")), 9)

    def test_force_whitelist(self):
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.patch_all()

        client = pyzor.client.BatchClient()
        for i in range(9):
            client.whitelist(digest)
        client.force()
        args, kwargs = list(self.get_requests())[0]

        msg = email.message_from_string(args[0])
        self.assertEqual(len(msg.get_all("Op-Digest")), 9)

    def test_flush_report(self):
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.patch_all()

        client = pyzor.client.BatchClient()
        for i in range(9):
            client.report(digest)
        client.flush()

        client.report(digest)
        self.assertEqual(list(self.get_requests()), [])

    def test_flush_whitelist(self):
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.patch_all()

        client = pyzor.client.BatchClient()
        for i in range(9):
            client.whitelist(digest)
        client.flush()

        client.whitelist(digest)
        self.assertEqual(list(self.get_requests()), [])


def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(ClientTest))
    test_suite.addTest(unittest.makeSuite(BatchClientTest))
    return test_suite

if __name__ == '__main__':
    unittest.main()
