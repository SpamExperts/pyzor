import os
import logging
import unittest
import ConfigParser

try:
    from unittest.mock import patch, Mock
except ImportError:
    from mock import patch, Mock


import pyzor.config

from tests.util import mock_open


class MockData(list):
    def close(self):
        pass


class TestPasswdLoad(unittest.TestCase):
    fp = "pyzord.passwd"
    alice_key = "alice_key"
    bob_key = "bob_key"

    def setUp(self):
        super(TestPasswdLoad, self).setUp()
        self.data = MockData()
        self.exists = True
        real_exists = os.path.exists
        patch("pyzor.config.open", return_value=self.data,
              create=True).start()
        _exists = lambda fp: True if fp == self.fp else real_exists(fp)
        patch("pyzor.config.os.path.exists", side_effect=_exists).start()

    def get_passwd(self, fp=None):
        if not fp:
            fp = self.fp
        return pyzor.config.load_passwd_file(fp)

    def tearDown(self):
        super(TestPasswdLoad, self).tearDown()
        patch.stopall()

    def test_nothing(self):
        result = self.get_passwd()
        self.assertEqual(result, {})

    def test_default(self):
        result = self.get_passwd("foobar")
        self.assertEqual(result, {})

    def test_passwd(self):
        self.data.append("alice : %s\n" % self.alice_key)
        self.data.append("bob : %s\n" % self.bob_key)
        result = self.get_passwd()
        self.assertEqual(result, {"alice": self.alice_key,
                                  "bob": self.bob_key})

    def test_invalid_line(self):
        self.data.append("alice ; %s\n" % self.alice_key)
        self.data.append("bob : %s\n" % self.bob_key)
        result = self.get_passwd()
        self.assertEqual(result, {"bob": self.bob_key})

    def test_ignore_comment(self):
        self.data.append("alice : %s\n" % self.alice_key)
        self.data.append("# bob : %s\n" % self.bob_key)
        result = self.get_passwd()
        self.assertEqual(result, {"alice": self.alice_key})


class TestAccessLoad(unittest.TestCase):
    fp = "pyzord.access"
    accounts = ["alice", "bob"]
    all = {'report', 'info', 'pong', 'ping', 'check', 'whitelist'}
    anonymous_privileges = {'report', 'info', 'pong', 'ping', 'check'}

    def setUp(self):
        super(TestAccessLoad, self).setUp()
        self.data = MockData()
        self.exists = True
        real_exists = os.path.exists
        patch("pyzor.config.open", return_value=self.data,
              create=True).start()
        _exists = lambda fp: True if fp == self.fp else real_exists(fp)
        patch("pyzor.config.os.path.exists", side_effect=_exists).start()

    def get_access(self, fp=None, accounts=None):
        if not fp:
            fp = self.fp
        if not accounts:
            accounts = self.accounts

        return pyzor.config.load_access_file(fp, accounts)

    def tearDown(self):
        super(TestAccessLoad, self).tearDown()
        patch.stopall()

    def test_nothing(self):
        result = self.get_access()
        self.assertEqual(result, {})

    def test_default(self):
        result = self.get_access(fp="foobar")
        self.assertEqual(result, {'anonymous': self.anonymous_privileges})

    def test_invalid_line(self):
        self.data.append("all : allice ; allow\n")
        self.data.append("ping : bob : allow\n")
        result = self.get_access()
        self.assertEqual(result, {'bob': {'ping'}})

    def test_invalid_action(self):
        self.data.append("all : allice : don't allow\n")
        self.data.append("ping : bob : allow\n")
        result = self.get_access()
        self.assertEqual(result, {'bob': {'ping'}})

    def test_all_privilege(self):
        self.data.append("all : bob : allow\n")
        result = self.get_access()
        self.assertEqual(result, {'bob': self.all})

    def test_all_accounts(self):
        self.data.append("all : all : allow\n")
        result = self.get_access()
        self.assertEqual(result, {'alice': self.all,
                                  'bob': self.all})

    def test_deny_action(self):
        self.data.append("all : all : allow\n")
        self.data.append("ping : bob : deny\n")
        result = self.get_access()
        self.assertEqual(result, {'alice': self.all,
                                  'bob': self.all - {'ping'}})

    def test_multiple_users(self):
        self.data.append("all : alice bob: allow\n")
        result = self.get_access()
        self.assertEqual(result, {'alice': self.all,
                                  'bob': self.all})

    def test_multiple_privileges(self):
        self.data.append("ping pong : alice: allow\n")
        result = self.get_access()
        self.assertEqual(result, {'alice': {'ping', 'pong'}})

    def test_ignore_comments(self):
        self.data.append("all: alice: allow\n")
        self.data.append("# all: bob : allow\n")
        result = self.get_access()
        self.assertEqual(result, {'alice': self.all})


class TestServersLoad(unittest.TestCase):
    fp = "servers"
    public_server = ("public.pyzor.org", 24441)
    random_server1 = ("random.pyzor.org", 33544)
    random_server2 = ("127.1.2.45", 13587)

    def setUp(self):
        super(TestServersLoad, self).setUp()
        self.data = []
        self.exists = True
        real_exists = os.path.exists
        _exists = lambda fp: True if fp == self.fp else real_exists(fp)
        patch("pyzor.config.os.path.exists", side_effect=_exists).start()

    def get_servers(self, fp=None):
        if not fp:
            fp = self.fp
        name = "pyzor.config.open"
        with patch(name, mock_open(read_data=''.join(self.data)),
                   create=True) as m:
            return pyzor.config.load_servers(fp)

    def tearDown(self):
        super(TestServersLoad, self).tearDown()
        patch.stopall()

    def test_nothing(self):
        result = self.get_servers()
        self.assertEqual(result, [self.public_server])

    def test_default(self):
        result = self.get_servers("foobar")
        self.assertEqual(result, [self.public_server])

    def test_servers(self):
        self.data.append("%s:%s\n" % self.random_server1)
        self.data.append("%s:%s\n" % self.random_server2)
        result = self.get_servers()
        self.assertEqual(result, [self.random_server1,
                                  self.random_server2])

    def test_ignore_comment(self):
        self.data.append("#%s:%s\n" % self.random_server1)
        self.data.append("%s:%s\n" % self.random_server2)
        result = self.get_servers()
        self.assertEqual(result, [self.random_server2])


class TestLogSetup(unittest.TestCase):
    log_file = "this_is_a_test_log_file"

    def setUp(self):
        super(TestLogSetup, self).setUp()

    def tearDown(self):
        super(TestLogSetup, self).tearDown()
        try:
            os.remove(self.log_file)
        except OSError:
            pass

    def test_logging(self):
        pyzor.config.setup_logging("pyzor.test1", None, False)
        log = logging.getLogger("pyzor.test1")
        self.assertEqual(log.getEffectiveLevel(), logging.INFO)

        self.assertEqual(log.handlers[0].level, logging.CRITICAL)

    def test_logging_debug(self):
        pyzor.config.setup_logging("pyzor.test2", None, True)
        log = logging.getLogger("pyzor.test2")
        self.assertEqual(log.getEffectiveLevel(), logging.DEBUG)

        self.assertEqual(log.handlers[0].level, logging.DEBUG)

    def test_logging_file(self):
        pyzor.config.setup_logging("pyzor.test3", self.log_file, False)
        log = logging.getLogger("pyzor.test3")
        self.assertEqual(log.getEffectiveLevel(), logging.INFO)

        self.assertEqual(log.handlers[0].level, logging.CRITICAL)
        self.assertEqual(log.handlers[1].level, logging.INFO)

    def test_logging_file_debug(self):
        pyzor.config.setup_logging("pyzor.test4", self.log_file, True)
        log = logging.getLogger("pyzor.test4")
        self.assertEqual(log.getEffectiveLevel(), logging.DEBUG)

        self.assertEqual(log.handlers[0].level, logging.DEBUG)
        self.assertEqual(log.handlers[1].level, logging.DEBUG)


class TestExpandHomeFiles(unittest.TestCase):
    home = "/home/user/pyzor"

    def setUp(self):
        super(TestExpandHomeFiles, self).setUp()

    def tearDown(self):
        super(TestExpandHomeFiles, self).tearDown()

    def check_expand(self, homefiles, homedir, config, expected):
        section = "test"
        conf = ConfigParser.ConfigParser()
        conf.add_section(section)
        for key, value in config.iteritems():
            conf.set(section, key, value)
        pyzor.config.expand_homefiles(homefiles, section, homedir, conf)
        result = dict(conf.items(section))
        self.assertEqual(result, expected)

    def test_homedir(self):
        self.check_expand(
            ["testfile"],
            self.home,
            {"testfile": "my.file"},
            {"testfile": "%s/my.file" % self.home},
        )

    def test_homedir_none(self):
        self.check_expand(
            ["testfile"],
            self.home,
            {"testfile": ""},
            {"testfile": ""},
        )

    def test_homedir_abs(self):
        self.check_expand(
            ["testfile"],
            self.home,
            {"testfile": "/home/user2/pyzor"},
            {"testfile": "/home/user2/pyzor"},
        )


def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestLogSetup))
    test_suite.addTest(unittest.makeSuite(TestAccessLoad))
    test_suite.addTest(unittest.makeSuite(TestPasswdLoad))
    test_suite.addTest(unittest.makeSuite(TestServersLoad))
    return test_suite


if __name__ == '__main__':
    unittest.main()

