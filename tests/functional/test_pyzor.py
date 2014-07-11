import sys
import redis
import unittest

from tests.util import *

class PyzorScriptTest(PyzorTestBase):
    password_file = None
    access = """ALL : anonymous : allow
"""

    def test_report_threshold(self):
        input = "Test1 report threshold 1  Test2"
        self.client_args["-r"] = "2"
        self.check_pyzor("report", None, input=input, code=200, exit_code=0)        
        self.check_pyzor("check", None, input=input, code=200, exit_code=1,
                         counts=(1, 0))
        self.check_pyzor("report", None, input=input, code=200, exit_code=0)
        self.check_pyzor("check", None, input=input, code=200, exit_code=1,
                         counts=(2, 0))
        # Exit code will be success now, since the report count exceeds the
        # threshold
        self.check_pyzor("report", None, input=input, code=200, exit_code=0)
        self.check_pyzor("check", None, input=input, code=200, exit_code=0,
                         counts=(3, 0))
        
    def test_whitelist_threshold(self):
        input = "Test1 white list threshold 1  Test2"
        self.client_args["-w"] = "2"
        self.check_pyzor("report", None, input=input, code=200, exit_code=0)        
        self.check_pyzor("check", None, input=input, code=200, exit_code=0,
                         counts=(1, 0))
        self.check_pyzor("whitelist", None, input=input, code=200, exit_code=0)
        self.check_pyzor("check", None, input=input, code=200, exit_code=0,
                         counts=(1, 1))
        self.check_pyzor("whitelist", None, input=input, code=200, exit_code=0)
        self.check_pyzor("check", None, input=input, code=200, exit_code=0,
                         counts=(1, 2))
        # Exit code will be failure now, since the whitelist count exceeds the
        # threshold
        self.check_pyzor("whitelist", None, input=input, code=200, exit_code=0)
        self.check_pyzor("check", None, input=input, code=200, exit_code=1,
                         counts=(1, 3))
    
    def test_report_whitelist_threshold(self):
        input = "Test1 report white list threshold 1  Test2"
        self.client_args["-w"] = "2"
        self.client_args["-r"] = "1"
        self.check_pyzor("report", None, input=input, code=200, exit_code=0)
        self.check_pyzor("check", None, input=input, code=200, exit_code=1,
                         counts=(1, 0))
        # Exit code will be success now, since the report count exceeds the
        # thresholdRedisPyzorTest
        self.check_pyzor("report", None, input=input, code=200, exit_code=0)
        self.check_pyzor("check", None, input=input, code=200, exit_code=0,
                         counts=(2, 0))        
        self.check_pyzor("whitelist", None, input=input, code=200, exit_code=0)
        self.check_pyzor("check", None, input=input, code=200, exit_code=0,
                         counts=(2, 1))
        self.check_pyzor("whitelist", None, input=input, code=200, exit_code=0)
        self.check_pyzor("check", None, input=input, code=200, exit_code=0,
                         counts=(2, 2))
        # Exit code will be failure now, since the whitelist count exceeds the
        # threshold
        self.check_pyzor("whitelist", None, input=input, code=200, exit_code=0)
        self.check_pyzor("check", None, input=input, code=200, exit_code=1,
                         counts=(2, 3))
    
    def test_digest_style(self):
        input = "da39a3ee5e6b4b0d3255bfef95601890afd80700"
        self.client_args["-s"] = "digests"
        self.check_pyzor("pong", None, input=input, code=200, exit_code=0,
                         counts=(sys.maxint, 0))
        self.check_pyzor("check", None, input=input, code=200, exit_code=1,
                         counts=(0, 0))
        self.check_pyzor("report", None, input=input, code=200, exit_code=0)
        self.check_pyzor("check", None, input=input, code=200, exit_code=0,
                         counts=(1, 0))
        self.check_pyzor("whitelist", None, input=input, code=200, exit_code=0)
        self.check_pyzor("check", None, input=input, code=200, exit_code=1,
                         counts=(1, 1))
        r = self.get_record(input, None)
        self.assertEqual(r["Count"], "1")
        self.assertEqual(r["WL-Count"], "1")
        
    def test_digest_style_multiple(self):
        input2 = "da39a3ee5e6b4b0d3255bfef95601890afd80705\n"\
                 "da39a3ee5e6b4b0d3255bfef95601890afd80706\n"
        input3 = "da39a3ee5e6b4b0d3255bfef95601890afd80705\n"\
                 "da39a3ee5e6b4b0d3255bfef95601890afd80706\n"\
                 "da39a3ee5e6b4b0d3255bfef95601890afd80707\n"
        self.client_args["-s"] = "digests"
        self.check_pyzor_multiple("pong", None, input=input3, exit_code=0,  
                                  code=[200, 200, 200],
                                  counts=[(sys.maxint, 0), 
                                          (sys.maxint, 0), 
                                          (sys.maxint, 0)])
        self.check_pyzor_multiple("check", None, input=input3, exit_code=1,  
                                  code=[200, 200, 200],
                                  counts=[(0, 0), (0, 0), (0, 0)])
        self.check_pyzor_multiple("report", None, input=input2, exit_code=0)                                    
        self.check_pyzor_multiple("check", None, input=input3, exit_code=0,  
                                  code=[200, 200, 200],
                                  counts=[(1, 0), (1, 0), (0, 0)])
        self.check_pyzor_multiple("whitelist", None, input=input3, exit_code=0)  
        self.check_pyzor_multiple("check", None, input=input3, exit_code=1,  
                                  code=[200, 200, 200],
                                  counts=[(1, 1), (1, 1), (0, 1)])                          
    
    def test_mbox_style(self):
        input = "From MAILER-DAEMON Mon Jan  6 15:13:33 2014\n\nTest1 message 0 Test2\n\n"
        self.client_args["-s"] = "mbox"
        self.check_pyzor("pong", None, input=input, code=200, exit_code=0,
                         counts=(sys.maxint, 0))
        self.check_pyzor("check", None, input=input, code=200, exit_code=1,
                         counts=(0, 0))
        self.check_pyzor("report", None, input=input, code=200, exit_code=0)
        self.check_pyzor("check", None, input=input, code=200, exit_code=0,
                         counts=(1, 0))
        self.check_pyzor("whitelist", None, input=input, code=200, exit_code=0)
        self.check_pyzor("check", None, input=input, code=200, exit_code=1,
                         counts=(1, 1))
        r = self.get_record(input, None)
        self.assertEqual(r["Count"], "1")
        self.assertEqual(r["WL-Count"], "1")
        
    def test_mbox_style_multiple(self):
        input2 = "From MAILER-DAEMON Mon Jan  6 15:08:02 2014\n\nTest1 message 1 Test2\n\n"\
                 "From MAILER-DAEMON Mon Jan  6 15:08:05 2014\n\nTest1 message 2 Test2\n\n"
        input3 = "From MAILER-DAEMON Mon Jan  6 15:08:02 2014\n\nTest1 message 1 Test2\n\n"\
                 "From MAILER-DAEMON Mon Jan  6 15:08:05 2014\n\nTest1 message 2 Test2\n\n"\
                 "From MAILER-DAEMON Mon Jan  6 15:08:08 2014\n\nTest1 message 3 Test2\n\n"
        self.client_args["-s"] = "mbox"
        self.check_pyzor_multiple("pong", None, input=input3, exit_code=0,  
                                  code=[200, 200, 200],
                                  counts=[(sys.maxint, 0), 
                                          (sys.maxint, 0), 
                                          (sys.maxint, 0)])
        self.check_pyzor_multiple("check", None, input=input3, exit_code=1, 
                                  code=[200, 200, 200],
                                  counts=[(0, 0), (0, 0), (0, 0)])
        self.check_pyzor_multiple("report", None, input=input2, exit_code=0)                                    
        self.check_pyzor_multiple("check", None, input=input3, exit_code=0,  
                                  code=[200, 200, 200],
                                  counts=[(1, 0), (1, 0), (0, 0)])
        self.check_pyzor_multiple("whitelist", None, input=input3, exit_code=0)  
        self.check_pyzor_multiple("check", None, input=input3, exit_code=1,  
                                  code=[200, 200, 200],
                                  counts=[(1, 1), (1, 1), (0, 1)])
        
    def test_predigest(self):
        out = self.check_pyzor("predigest", None, input=msg).strip()
        self.assertEqual(out.decode("utf8"), "TestEmail")
        
    def test_digest(self):
        out = self.check_pyzor("digest", None, input=msg).strip()
        self.assertEqual(out.decode("utf8"), digest)
        
class MultipleServerPyzorScriptTest(PyzorTestBase):
    password_file = None
    access = """ALL : anonymous : allow
"""
    servers = """127.0.0.1:9999
127.0.0.1:9998
127.0.0.1:9997
"""

    def test_ping(self):
        self.check_pyzor_multiple("ping", None, exit_code=0,
                                  code=[200, 200, 200])

    def test_pong(self):
        input = "Test1 multiple pong Test2"
        self.check_pyzor_multiple("pong", None, input=input, exit_code=0,
                                  code=[200, 200, 200],
                                  counts=[(sys.maxint, 0),
                                          (sys.maxint, 0),
                                          (sys.maxint, 0)])

    def test_check(self):
        input = "Test1 multiple check Test2"
        self.check_pyzor_multiple("check", None, input=input, exit_code=1,
                                  code=[200, 200, 200],
                                  counts=[(0, 0), (0, 0), (0, 0)])

    def test_report(self):
        input = "Test1 multiple report Test2"
        self.check_pyzor_multiple("report", None, input=input, exit_code=0,
                                  code=[200, 200, 200])

    def test_whitelist(self):
        input = "Test1 multiple whitelist Test2"
        self.check_pyzor_multiple("whitelist", None, input=input, exit_code=0,
                                  code=[200, 200, 200])


def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(PyzorScriptTest))
    test_suite.addTest(unittest.makeSuite(MultipleServerPyzorScriptTest))
    return test_suite
        
if __name__ == '__main__':
    unittest.main()
