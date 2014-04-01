import sys
import time
import socket
import unittest

import pyzor
import pyzor.client
import pyzor.account

def make_MockSocket(response, request):
    """Create a MockSocket class that will append requests to
    the specified `request` list and return the specified `response`  
    """
    class MockSocket():        
        def __init__(self, *args, **kwargs):
            pass        
        def settimeout(self, timeout):
            pass        
        def recvfrom(self, packetsize):
            return response, ("127.0.0.1", 24441)
        def sendto(self, data, flag, address):
            request.append(data)
    return MockSocket

def make_MockThreadId(thread):
    """Creates a MockThreadId class that will generate 
    the specified thread number.
    """
    class MockThreadId(int):
        def __new__(cls, i):
            return int.__new__(cls, i)
        @classmethod
        def generate(cls):
            return thread
    
        def in_ok_range(self):
            return True
    return MockThreadId

def mock_sign_msg(hash_key, timestamp, msg):
    return "TestSig"

def mock_hash_key(user_key, user):
    return None

class ClientTest(unittest.TestCase):
    
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.real_sg = pyzor.account.sign_msg
        pyzor.account.sign_msg = mock_sign_msg
        self.real_hk = pyzor.account.hash_key
        pyzor.account.hash_key = mock_hash_key
        self.thread = 33715
        
        # the response the mock socket will send
        self.response = "Code: 200\nDiag: OK\nPV: 2.1\nThread: 33715\n\n"
        # the requests send by the client will be stored here
        self.request = []
        # the expected request that the client should send
        self.expected = {"Thread": str(self.thread),
                         "PV": str(pyzor.proto_version),
                         "User": "anonymous",
                         "Time": str(int(time.time())),
                         "Sig": "TestSig"}
    
    def tearDown(self):
        unittest.TestCase.tearDown(self)
        pyzor.account.sign_msg = self.real_sg
        pyzor.account.hash_key = self.real_hk
    
    def check_request(self, request):
        """Check if the request sent by the client is equal 
        to the expected one.
        """
        req = {}
        request = request.decode("utf8").replace("\n\n", "\n")
        for line in request.splitlines():
            key = line.split(":")[0].strip()
            value = line.split(":")[1].strip()
            req[key] = value
        self.assertEqual(req, self.expected)            

    def check_client(self, accounts, method, *args, **kwargs):
        """Tests if the request and response are sent
        and read correctly by the client.
        """
        real_socket = socket.socket
        socket.socket = make_MockSocket(self.response.encode("utf8"), 
                                        self.request)

        real_ThreadId = pyzor.ThreadId
        pyzor.ThreadId = make_MockThreadId(self.thread)
        client = pyzor.client.Client(accounts)
        try:
            response = getattr(client, method)(*args, **kwargs)
            self.assertEqual(str(response), self.response)
            self.check_request(self.request[0])
        finally:
            socket.socket = real_socket
            pyzor.ThreadId = real_ThreadId
        return client 

    def test_ping(self):
        """Test the client ping request"""
        self.expected["Op"] = "ping"
        self.check_client(None, "ping")

    def test_pong(self):
        """Test the client pong request"""        
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.expected["Op"] = "pong"
        self.expected["Op-Digest"] = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.check_client(None, "pong", digest)    

    def test_check(self):
        """Test the client check request"""        
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.expected["Op"] = "check"
        self.expected["Op-Digest"] = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.check_client(None, "check", digest)        

    def test_info(self):
        """Test the client info request"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.expected["Op"] = "info"
        self.expected["Op-Digest"] = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.check_client(None, "info", digest)

    def test_report(self):
        """Test the client report request"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.expected["Op"] = "report"
        self.expected["Op-Digest"] = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.expected["Op-Spec"] = "20,3,60,3"
        self.check_client(None, "report", digest)

    def test_whitelist(self):
        """Test the client whitelist request"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.expected["Op"] = "whitelist"
        self.expected["Op-Digest"] = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        self.expected["Op-Spec"] = "20,3,60,3"
        self.check_client(None, "whitelist", digest)
        
    def test_handle_account(self):
        """Test client handling accounts"""
        test_account = pyzor.account.Account("TestUser", "TestKey", "TestSalt")
        self.expected["Op"] = "ping"
        self.expected["User"] = "TestUser"
        self.check_client({("public.pyzor.org", 24441): test_account}, "ping")
    
    def test_handle_invalid_thread(self):
        """Test invalid thread id"""
        self.thread += 20
        self.expected["Op"] = "ping"
        self.assertRaises(pyzor.ProtocolError, self.check_client, None, "ping")
        
def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(ClientTest))
    return test_suite

if __name__ == '__main__':
    unittest.main()

