import sys
import unittest
import StringIO

sys.path.insert(0, './lib')
from pyzor import *
from pyzor.server import *
from pyzor.client import *

__revision__ = "$Id: unittests.py,v 1.7 2002-09-04 20:34:47 ftobin Exp $"


class ACLTest(unittest.TestCase):
    def setUp(self):
        access_file = AccessFile(StringIO.StringIO("""check : alice : allow
        # comment
        check : bob : deny
        report check : all : allow
        ping : all : deny
        all : charlie : allow
        all : all : allow
        all : all : deny
        """))

        self.acl = ACL()
        access_file.feed_into(self.acl)

    def test_basic_allow(self):
        self.assert_(self.acl.allows(Username('alice'), Opname('check')))

    def test_basic_deny(self):
        self.assert_(not self.acl.allows(Username('bob'), Opname('check')))

    def test_all_user_allow(self):
        self.assert_(self.acl.allows(Username('dennis'), Opname('report')))
        self.assert_(self.acl.allows(Username('bob'), Opname('report')))

    def test_all_user_deny(self):
        self.assert_(not self.acl.allows(Username('alice'), Opname('ping')))
        self.assert_(not self.acl.allows(Username('frank'), Opname('ping')))

    def test_allow_user_all_ops(self):
        self.assert_(self.acl.allows(Username('charlie'), Opname('check')))
        self.assert_(self.acl.allows(Username('charlie'), Opname('foobar')))
        
    def test_all_allowed_all(self):
        self.assert_(self.acl.allows(Username('giggles'), Opname('report')))
        self.assert_(self.acl.allows(Username('zoe'), Opname('foobar')))



class PasswdTest(unittest.TestCase):
    def setUp(self):
        passwd_file = PasswdFile(StringIO.StringIO("""alice:5
        bob:b
        charlie:cc
        """))

        self.passwd = Passwd()
        for u,k in passwd_file:
            self.passwd[u] = k
        
    def test_keys(self):
        self.assertEquals(self.passwd[Username('alice')], 5L)
        self.assertEquals(self.passwd[Username('bob')], 11L)
        self.assertEquals(self.passwd[Username('charlie')], 204L)

    def test_no_user(self):
        self.assert_(not self.passwd.has_key(Username('foobar')))


class AcountInfoTest(unittest.TestCase):
    def setUp(self):
        account_file = AccountsFile(StringIO.StringIO("""127.0.0.0 : 3333 : alice : 5,a
        # comment
        127.0.0.1 : 4444 : bob : ,18
        """))
        
##        # For testing in the future
##        127.0.0.1 : 4445 : charlie : c,
##        127.0.0.1 : 4446 : david : ,

        self.accounts = AccountsDict()

        for addr, acc in account_file:
            self.accounts[addr] = acc

    def test_full_key(self):
        self.assertEquals(self.accounts[Address(('127.0.0.0', 3333))],
                          Account((Username('alice'),
                                   Keystuff((5L, 10L)))))

    def test_only_key(self):
        self.assertEquals(self.accounts[Address(('127.0.0.1', 4444))],
                          Account((Username('bob'),
                                   Keystuff((None, 24L)))))

##    def test_only_salt(self):
##       self.assertEquals(self.accounts[Address(('127.0.0.1', 4445))],
##                         Account((Username('charlie'),
##                                  Keystuff((None, 12)))))
        

##    def test_neither(self):
##        self.assertEquals(self.accounts[Address(('127.0.0.1', 4446))],
##                          Account((Username('david'),
##                                   Keystuff((None, 24)))))



class KeystuffTest(unittest.TestCase):
    def test_full_stuff(self):
        self.assertEquals(Keystuff.from_hexstr("10,ab"),
                          Keystuff((16L, 171L)))

    def test_only_key(self):
        self.assertEquals(Keystuff.from_hexstr(",ab"),
                          Keystuff((None, 171L)))



class ServerListTest(unittest.TestCase):
    def setUp(self):
        self.sl = ServerList()

        self.sl.read(StringIO.StringIO("""127.0.0.1:4444
        # comment
        127.0.0.2:1234
        """))

    def test_sl_length(self):
        self.assertEquals(len(self.sl), 2)

    def test_entries(self):
        self.assert_(Address(('127.0.0.1', 4444)) in self.sl)
        self.assert_(Address(('127.0.0.2', 1234)) in self.sl)



class DataDigestTest(unittest.TestCase):
    def test_ptrns(self):
        norm = DataDigester.normalize
        self.assertEqual(norm('aaa me@example.com bbb'), 'aaabbb')
        self.assertEqual(norm('aaa http://www.example.com/ bbb'), 'aaabbb')
        self.assertEqual(norm('aaa Supercalifragilisticexpialidocious bbb'),
                         'aaabbb')
        self.assertEqual(norm('aaa  bbb  ccc\n'), 'aaabbbccc')
        self.assertEqual(norm('aaa <! random tag > bbb'), 'aaabbb')

    def test_should_handle_line(self):
        min_len = int(DataDigester.min_line_length)
        self.assert_(DataDigester.should_handle_line('a' * min_len))
        self.assert_(not DataDigester.should_handle_line('a' * (min_len-1)))


    def test_atomicness(self):
        self.assert_(DataDigester(open('t/atomic'),
                                  ExecCall.digest_spec,
                                  seekable=True).is_atomic())

    def test_non_atomicness(self):
        self.assert_(not DataDigester(open('t/atomic.not'),
                                      ExecCall.digest_spec,
                                      seekable=True).is_atomic())


class rfc822BodyCleanerTest(unittest.TestCase):
    def test_cleaning(self):
        expected = open('t/multipart.expected')
        for line in rfc822BodyCleaner(open('t/multipart')):
            self.assertEqual(line, expected.readline())



if __name__ == "__main__":
    unittest.main()
