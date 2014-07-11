"""Test the pyzor.server module
"""
import io
import sys
import time
import logging
import unittest
import SocketServer

from datetime import datetime, timedelta

import pyzor.server
import pyzor.engines.common

class MockServer():
    """Mocks the pyzor.server.Server class"""
    
    def __init__(self):
        self.log = logging.getLogger("pyzord")
        self.usage_log = logging.getLogger("pyzord-usage")
        self.log.addHandler(logging.NullHandler())
        self.usage_log.addHandler(logging.NullHandler())
        self.forwarder = None
        
        
class MockDatagramRequestHandler():
    """ Mock the SocketServer.DatagramRequestHand."""
    
    def __init__(self, headers, database=None, acl=None, accounts=None):
        """Initiates an request handler and set's the data in `headers` as 
        the request. Also set's the database, acl and accounts for the 
        MockServer. 
        
        This will be set as base class for RequestHandler. 
        """
        self.rfile = io.BytesIO()
        self.wfile = io.BytesIO()
        for i, j in headers.iteritems():
            self.rfile.write(("%s: %s\n" % (i, j)).encode("utf8"))
        self.rfile.seek(0)
        self.packet = None
        self.client_address = ["127.0.0.1"]        
        
        # Setup MockServer data
        self.server = MockServer()
        self.server.database = database
        if acl:
            self.server.acl = acl
        else:
            self.server.acl = {pyzor.anonymous_user: ("check", "report", "ping", "info", "whitelist",)}
        self.server.accounts = accounts                
        
        self.handle()
            
    def handle(self):
        pass


class RequestHandlerTest(unittest.TestCase):            
    
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.real_drh = SocketServer.DatagramRequestHandler
        SocketServer.DatagramRequestHandler = MockDatagramRequestHandler
        pyzor.server.RequestHandler.__bases__ = (MockDatagramRequestHandler,)
        
        # setup the basic values for request and response
        self.request = {"User": pyzor.anonymous_user,
                        "Time": str(int(time.time())),
                        "PV": str(pyzor.proto_version),
                        "Thread": "3597"}
        self.expected_response = {"Code": "200",
                                  "Diag": "OK",
                                  "PV": str(pyzor.proto_version),
                                  "Thread": "3597"}
        
    def tearDown(self):
        unittest.TestCase.tearDown(self)
        SocketServer.DatagramRequestHandler = self.real_drh
        pyzor.server.RequestHandler.__bases__ = (self.real_drh,)
    
    def check_response(self, handler):
        """Checks if the response from the handler is equal to
        the expected response.
        """
        handler.wfile.seek(0)
        response = handler.wfile.read()
        response = response.decode("utf8").replace("\n\n", "\n")

        result = {}
        try:
            for line in response.splitlines():
                key = line.split(":", 1)[0].strip()
                value = line.split(":")[1].strip()
                result[key] = value
        except (IndexError, TypeError) as e:
            self.fail("Error parsing %r: %s" % (response, e))
        
        self.assertEqual(result, self.expected_response)            
    
    def timestamp(self, time_obj):
        if not time_obj:
            return 0
        else:
            return str(int(time.mktime(time_obj.timetuple())))
    
    def test_ping(self):
        """Tests the ping command handler"""
        self.request["Op"] = "ping"
        handler = pyzor.server.RequestHandler(self.request)
        
        self.check_response(handler)
    
    def test_pong(self):
        """Tests the pong command handler"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        database = {digest: pyzor.engines.common.Record(24, 42)}
        
        self.request["Op"] = "pong"
        self.request["Op-Digest"] = digest
        pyzor.server.RequestHandler(self.request, database)
        self.expected_response["Count"] = str(sys.maxint) 
        self.expected_response["WL-Count"] = "0"

    def test_check(self):
        """Tests the check command handler"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        database = {digest: pyzor.engines.common.Record(24, 42)}
        
        self.request["Op"] = "check"
        self.request["Op-Digest"] = digest
        handler = pyzor.server.RequestHandler(self.request, database)
        self.expected_response["Count"] = "24"
        self.expected_response["WL-Count"] = "42"
        
        self.check_response(handler)
        
    def test_check_new(self):
        """Tests the check command handler with a new record"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        database = {}
        
        self.request["Op"] = "check"
        self.request["Op-Digest"] = digest
        handler = pyzor.server.RequestHandler(self.request, database)
        self.expected_response["Count"] = "0"
        self.expected_response["WL-Count"] = "0"
        
        self.check_response(handler)
    
    def test_info(self):
        """Tests the info command handler"""
        entered = datetime.now() - timedelta(days=10)
        updated = datetime.now()
        wl_entered = datetime.now() - timedelta(days=20)
        wl_updated = datetime.now() - timedelta(days=2)
                
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        database = {digest: pyzor.engines.common.Record(24, 42, entered, updated,
                                                        wl_entered, wl_updated)}        
        self.request["Op"] = "info"
        self.request["Op-Digest"] = digest
        handler = pyzor.server.RequestHandler(self.request, database)
        self.expected_response["Count"] = "24"
        self.expected_response["WL-Count"] = "42"
        self.expected_response["Entered"] = self.timestamp(entered)
        self.expected_response["Updated"] = self.timestamp(updated)
        self.expected_response["WL-Entered"] = self.timestamp(wl_entered)
        self.expected_response["WL-Updated"] = self.timestamp(wl_updated)
        
        self.check_response(handler)
        
    def test_info_new(self):
        """Tests the info command handler with a new record"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        database = {}        
        self.request["Op"] = "info"
        self.request["Op-Digest"] = digest
        handler = pyzor.server.RequestHandler(self.request, database)
        self.expected_response["Count"] = "0"
        self.expected_response["WL-Count"] = "0"
        self.expected_response["Entered"] = "0"
        self.expected_response["Updated"] = "0"
        self.expected_response["WL-Entered"] = "0"
        self.expected_response["WL-Updated"] = "0"
        
        self.check_response(handler)
        
    def test_report(self):
        """Tests the report command handler"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        database = {digest: pyzor.engines.common.Record(24, 42)}
         
        self.request["Op"] = "report"
        self.request["Op-Digest"] = digest
        handler = pyzor.server.RequestHandler(self.request, database)
        
        self.check_response(handler)
        self.assertEqual(database[digest].r_count, 25)            
        
    def test_report_new(self):
        """Tests the report command handler with a new record"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        database = {}
         
        self.request["Op"] = "report"
        self.request["Op-Digest"] = digest
        handler = pyzor.server.RequestHandler(self.request, database)
        
        self.check_response(handler)
        self.assertEqual(database[digest].r_count, 1)   
        
    def test_whitelist(self):
        """Tests the whitelist command handler"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        database = {digest: pyzor.engines.common.Record(24, 42)}
         
        self.request["Op"] = "whitelist"
        self.request["Op-Digest"] = digest
        handler = pyzor.server.RequestHandler(self.request, database)
        
        self.check_response(handler)
        self.assertEqual(database[digest].wl_count, 43)            
        
    def test_whitelist_new(self):
        """Tests the whitelist command handler with a new record"""
        digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
        database = {}
         
        self.request["Op"] = "whitelist"
        self.request["Op-Digest"] = digest
        handler = pyzor.server.RequestHandler(self.request, database)
        
        self.check_response(handler)
        self.assertEqual(database[digest].wl_count, 1)
    
    def test_handle_no_version(self):
        """Tests handling an request with no version specified"""
        self.request["Op"] = "ping"
        del self.request["PV"]
        handler = pyzor.server.RequestHandler(self.request)
        
        self.expected_response["Code"] = "400"
        self.expected_response["Diag"] = "Bad request"
        self.check_response(handler)
    
    def test_handle_unsupported_version(self):
        """Tests handling an request with an unsupported version specified"""
        self.request["Op"] = "ping"
        self.request["PV"] = str(pyzor.proto_version + 2)
        handler = pyzor.server.RequestHandler(self.request)
        
        self.expected_response["Code"] = "505"
        self.expected_response["Diag"] = "Version Not Supported"
        self.check_response(handler)        
    
    def test_handle_not_implemented(self):
        """Tests handling an request with an unimplemented command"""
        self.request["Op"] = "notimplemented"
        acl = {pyzor.anonymous_user: "notimplemented"}
        handler = pyzor.server.RequestHandler(self.request, acl=acl)
        
        self.expected_response["Code"] = "501"
        self.expected_response["Diag"] = "Not implemented"
        self.check_response(handler)

    def test_handle_unauthorized(self):
        """Tests handling an request with an unauthorized command"""
        self.request["Op"] = "report"
        acl = {pyzor.anonymous_user: ("ping", "check")}
        handler = pyzor.server.RequestHandler(self.request, acl=acl)
        
        self.expected_response["Code"] = "403"
        self.expected_response["Diag"] = "Forbidden"
        self.check_response(handler)
        
    def test_handle_account(self):
        """Tests handling an request where user is not anonymous"""
        self.request["Op"] = "ping"
        self.request["User"] = "testuser"
        acl = {"testuser": ("ping", "check")}
        accounts = {"testuser": "testkey"}
                
        mock_vs = lambda x, y: None
        real_vs = pyzor.account.verify_signature
        pyzor.account.verify_signature = mock_vs
        try:
            handler = pyzor.server.RequestHandler(self.request, acl=acl,
                                                  accounts=accounts)
            self.check_response(handler)
        finally:
            pyzor.account.verify_signature = real_vs
    
    def test_handle_unknown_account(self):
        """Tests handling an request where user is unkwown"""
        self.request["Op"] = "ping"
        self.request["User"] = "testuser"
        acl = {"testuser": ("ping", "check")}
        accounts = {}
        
        self.expected_response["Code"] = "401"
        self.expected_response["Diag"] = "Unauthorized"
        
        def mock_vs(x, y):
            pass        
        real_vs = pyzor.account.verify_signature
        pyzor.account.verify_signature = mock_vs
        try:
            handler = pyzor.server.RequestHandler(self.request, acl=acl,
                                                  accounts=accounts)
            self.check_response(handler)
        finally:
            pyzor.account.verify_signature = real_vs

    def test_handle_invalid_signature(self):
        """Tests handling an request where user key is invalid"""
        self.request["Op"] = "ping"
        self.request["User"] = "testuser"
        acl = {"testuser": ("ping", "check")}
        accounts = {"testuser": ("ping", "check")}
        
        self.expected_response["Code"] = "401"
        self.expected_response["Diag"] = "Unauthorized"
        
        def mock_vs(x, y):
            raise pyzor.SignatureError("Invalid signature.")        
        real_vs = pyzor.account.verify_signature
        pyzor.account.verify_signature = mock_vs
        try:
            handler = pyzor.server.RequestHandler(self.request, acl=acl,
                                                  accounts=accounts)
            self.check_response(handler)
        finally:
            pyzor.account.verify_signature = real_vs

def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(RequestHandlerTest))
    return test_suite

if __name__ == '__main__':
    unittest.main()
