"""Test the pyzor.account module
"""
import os
import sys
import time
import email
import hashlib
import unittest
import StringIO

import pyzor
import pyzor.account

class AccountTest(unittest.TestCase):            
    
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.timestamp = 1381219396
        self.msg = email.message_from_string("") 
        self.msg["Op"] = "ping"
        self.msg["Thread"] = "14941"
        self.msg["PV"] = "2.1"
        self.msg["User"] = "anonymous"
        self.msg["Time"] = str(self.timestamp)
    
    def tearDown(self):
        unittest.TestCase.tearDown(self)
        
    def test_sign_msg(self):
        """Test the sign message function"""
        hashed_key = hashlib.sha1(b"test_key").hexdigest()
        expected = "2ab1bad2aae6fd80c656a896c82eef0ec1ec38a0"
        result = pyzor.account.sign_msg(hashed_key, self.timestamp, self.msg)
        self.assertEqual(result, expected)
    
    def test_hash_key(self):
        """Test the hash key function"""
        user = "testuser"
        key = "testkey"
        expected = "0957bd79b58263657127a39762879098286d8477"
        result = pyzor.account.hash_key(key, user)
        self.assertEqual(result, expected)
    
    def test_verify_signature(self):
        """Test the verify signature function"""
        def mock_sm(h, t, m):
            return "testsig"
        real_sm = pyzor.account.sign_msg
        pyzor.account.sign_msg = mock_sm
        try:
            self.msg["Sig"] = "testsig"
            del self.msg["Time"]
            self.msg["Time"] = str(int(time.time()))            
            pyzor.account.verify_signature(self.msg, "testkey")
        finally:
            pyzor.account.sign_msg = real_sm
    
    def test_verify_signature_old_timestamp(self):
        """Test the verify signature with old timestamp"""
        def mock_sm(h, t, m):
            return "testsig"
        real_sm = pyzor.account.sign_msg
        pyzor.account.sign_msg = mock_sm
        try:
            self.msg["Sig"] = "testsig"            
            self.assertRaises(pyzor.SignatureError, pyzor.account.verify_signature, self.msg, "testkey")
        finally:
            pyzor.account.sign_msg = real_sm
    
    def test_verify_signature_bad_signature(self):
        """Test the verify signature with invalid signature"""
        def mock_sm(h, t, m):
            return "testsig"
        real_sm = pyzor.account.sign_msg
        pyzor.account.sign_msg = mock_sm
        try:
            self.msg["Sig"] = "testsig-bad"
            del self.msg["Time"]
            self.msg["Time"] = str(int(time.time()))            
            self.assertRaises(pyzor.SignatureError, pyzor.account.verify_signature, self.msg, "testkey")
        finally:
            pyzor.account.sign_msg = real_sm

class LoadAccountTest(unittest.TestCase):            
    """Tests for the load_accounts function"""
    def setUp(self):
        unittest.TestCase.setUp(self)
        
        self.real_exists = os.path.exists
        os.path.exists = lambda p: True
        self.mock_file = StringIO.StringIO()
        self.real_open = pyzor.account.__builtins__["open"]
        def mock_open(path, mode="r", buffering=-1):
            if path == "test_file":
                self.mock_file.seek(0)
                return self.mock_file
            else:
                return self.real_open(path, mode, buffering)        
        pyzor.account.__builtins__["open"] = mock_open                 
    
    def tearDown(self):
        unittest.TestCase.tearDown(self)
        os.path.exists = self.real_exists
        pyzor.account.__builtins__["open"] = self.real_open
    
    def test_load_accounts(self):
        """Test loading the account file"""
        self.mock_file.write("public.pyzor.org : 24441 : test : 123abc,cba321\n"
                             "public2.pyzor.org : 24441 : test2 : 123abc,cba321")
        result = pyzor.account.load_accounts("test_file")
        self.assertIn(("public.pyzor.org", 24441), result)
        self.assertIn(("public2.pyzor.org", 24441), result)
        account = result[("public.pyzor.org", 24441)]
        self.assertEqual((account.username, account.salt, account.key),
                         ("test", "123abc", "cba321"))
        account = result[("public2.pyzor.org", 24441)]
        self.assertEqual((account.username, account.salt, account.key),
                         ("test2", "123abc", "cba321"))
        
    def test_load_accounts_comment(self):
        """Test skipping commented lines"""
        self.mock_file.write("#public1.pyzor.org : 24441 : test : 123abc,cba321")
        result = pyzor.account.load_accounts("test_file")
        self.assertNotIn(("public.pyzor.org", 24441), result)
        self.assertFalse(result)       

def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(AccountTest))
    test_suite.addTest(unittest.makeSuite(LoadAccountTest))
    return test_suite

if __name__ == '__main__':
    unittest.main()
    
        
        
