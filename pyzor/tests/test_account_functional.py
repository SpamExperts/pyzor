import unittest

from util import *

class AccountPyzorTest(PyzorTestBase):
    
    # test bob which has access to everything
    def test_ping(self):
        self.check_pyzor("ping", "bob", code=200, exit_code=0)

    def test_pong(self):
        self.check_pyzor("pong", "bob", input=msg, code=200, exit_code=0)
    
    def test_check(self):
        self.check_pyzor("check", "bob", input=msg, code=200)
    
    def test_report(self):
        self.check_pyzor("report", "bob", input=msg, code=200, exit_code=0)
    
    def test_whitelist(self):
        self.check_pyzor("whitelist", "bob", input=msg, code=200, exit_code=0)

    def test_info(self):
        self.check_pyzor("info", "bob", input=msg, code=200, exit_code=0)
    
    # test alice which does not has access to anything
    # Error should be 403 Forbidden    
    def test_ping_forbidden(self):
        self.check_pyzor("ping", "alice", code=403, exit_code=1)

    def test_pong_forbidden(self):
        self.check_pyzor("pong", "alice", input=msg, code=403, exit_code=1)
    
    def test_check_forbidden(self):
        self.check_pyzor("check", "alice", input=msg, code=403, exit_code=1)
    
    def test_report_forbidden(self):
        self.check_pyzor("report", "alice", input=msg, code=403, exit_code=1)
    
    def test_whitelist_forbidden(self):
        self.check_pyzor("whitelist", "alice", input=msg, code=403, exit_code=1)

    def test_info_forbidden(self):
        self.check_pyzor("info", "alice", input=msg, code=403, exit_code=1)

    # test chuck which does tries to steal bob's account but has the wrong key
    # Error should be 401 Unauthorized
    def test_ping_unauthorized(self):
        self.check_pyzor("ping", "chuck", code=401, exit_code=1)

    def test_pong_unauthorized(self):
        self.check_pyzor("pong", "chuck", input=msg, code=401, exit_code=1)
    
    def test_check_unauthorized(self):
        self.check_pyzor("check", "chuck", input=msg, code=401, exit_code=1)
    
    def test_report_unauthorized(self):
        self.check_pyzor("report", "chuck", input=msg, code=401, exit_code=1)
    
    def test_whitelist_unauthorized(self):
        self.check_pyzor("whitelist", "chuck", input=msg, code=401, exit_code=1)

    def test_info_unauthorized(self):
        self.check_pyzor("info", "chuck", input=msg, code=401, exit_code=1)
    
    # test dan account, which has some access
    def test_ping_combo(self):
        self.check_pyzor("ping", "dan", code=200, exit_code=0)

    def test_pong_combo(self):
        self.check_pyzor("pong", "dan", input=msg, code=403, exit_code=1)
    
    def test_check_combo(self):
        self.check_pyzor("check", "dan", input=msg, code=200)
    
    def test_report_combo(self):
        self.check_pyzor("report", "dan", input=msg, code=200, exit_code=0)
    
    def test_whitelist_combo(self):
        self.check_pyzor("whitelist", "dan", input=msg, code=403, exit_code=1)

    def test_info_combo(self):
        self.check_pyzor("info", "dan", input=msg, code=403, exit_code=1)
    
    # test anonymous account, which should is not currently set up in the server    
    def test_ping_anonymous(self):
        self.check_pyzor("ping", None, code=403, exit_code=1)

    def test_pong_anonymous(self):
        self.check_pyzor("pong", None, input=msg, code=403, exit_code=1)
    
    def test_check_anonymous(self):
        self.check_pyzor("check", None, input=msg, code=403, exit_code=1)
    
    def test_report_anonymous(self):
        self.check_pyzor("report", None, input=msg, code=403, exit_code=1)
    
    def test_whitelist_anonymous(self):
        self.check_pyzor("whitelist", None, input=msg, code=403, exit_code=1)

    def test_info_anonymous(self):
        self.check_pyzor("info", None, input=msg, code=403, exit_code=1)
    
class AnonymousPyzorTest(PyzorTestBase):
    """Test accounts with no access or password file set-up. And test 
    anonymous default access.
    """
    access_file = None
    password_file = None
    def test_ping(self):
        self.check_pyzor("ping", None, code=200, exit_code=0)

    def test_pong(self):
        self.check_pyzor("pong", None, input=msg, code=200, exit_code=0)
    
    def test_check(self):
        self.check_pyzor("check", None, input=msg, code=200)
    
    def test_report(self):
        self.check_pyzor("report", None, input=msg, code=200, exit_code=0)
    
    def test_whitelist(self):
        # anonymous account are not allowed to whitelist by default
        self.check_pyzor("whitelist", None, input=msg, code=403, exit_code=1)

    def test_info(self):
        self.check_pyzor("info", None, input=msg, code=200, exit_code=0)

def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(AccountPyzorTest))
    test_suite.addTest(unittest.makeSuite(AnonymousPyzorTest))
    return test_suite
        
if __name__ == '__main__':
    unittest.main()
            