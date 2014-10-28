"""This package contains various utilities use in the pyzor tests."""

import os
import sys
import time
import redis
import shutil
import unittest
import subprocess

from datetime import datetime

try:
    from unittest.mock import mock_open as _mock_open
except ImportError:
    from mock import mock_open as _mock_open

import pyzor.client

def mock_open(mock=None, read_data=""):
    mock = _mock_open(mock, read_data)
    mock.return_value.__iter__ = lambda x: iter(read_data.splitlines())
    return mock

msg = """Newsgroups:
Date: Wed, 10 Apr 2002 22:23:51 -0400 (EDT)
From: Frank Tobin <ftobin@neverending.org>
Fcc: sent-mail
Message-ID: <20020410222350.E16178@palanthas.neverending.org>
X-Our-Headers: X-Bogus,Anon-To
X-Bogus: aaron7@neverending.org
MIME-Version: 1.0
Content-Type: TEXT/PLAIN; charset=US-ASCII

Test Email
"""

digest = "7421216f915a87e02da034cc483f5c876e1a1338"

_dt_decode = lambda x: None if x == 'None' else datetime.strptime(x, "%a %b %d %H:%M:%S %Y")

class PyzorTestBase(unittest.TestCase):
    """Test base that starts the pyzord daemon in setUpClass with specified
    arguments. The daemon is killed in tearDownClass. This also create the
    necessary files and the homedir.
    """
    pyzord = None
    _args = {"homedir": "--homedir",
             "engine": "-e",
             "dsn": "--dsn",
             "address": "-a",
             "port": "-p",
             "threads": "--threads",
             "max_threads": "--max-threads",
             "processes": "--processes",
             "max_processes": "--max-processes",
             "db_connections": "--db-connections",
             "password_file": "--password-file",
             "access_file": "--access-file",
             "cleanup_age": "--cleanup-age",
             "log_file": "--log-file",
             "detach": "--detach",
             "prefork": "--pre-fork",
             }
    homedir = "./pyzor-test/"
    threads = "False"
    access_file = "pyzord.access"
    password_file = "pyzord.passwd"
    log_file = "pyzord-test.log"

    dsn = "localhost,,,10"
    engine = "redis"

    access = """check report ping pong info whitelist : alice : deny
                check report ping pong info whitelist : bob : allow
                ALL : dan : allow
                pong info whitelist : dan : deny
"""
    passwd = """alice : fc7f1cad729b5f3862b2ef192e2d9e0d0d4bd515
                bob : cf88277c5d4abdc0a3f56f416011966d04a3f462
                dan : c1a50281fc43e860fe78c16c73b9618ada59f959
"""
    servers = """127.0.0.1:9999
"""
    accounts_alice = """127.0.0.1 : 9999 : alice : d28f86151e80a9accba4a4eba81c460532384cd6,fc7f1cad729b5f3862b2ef192e2d9e0d0d4bd515
"""
    accounts_bob = """127.0.0.1 : 9999 : bob : de6ef568787256bf5f55909dc0c398e49b5c9808,cf88277c5d4abdc0a3f56f416011966d04a3f462
"""
    accounts_chuck = """127.0.0.1 : 9999 : bob : de6ef568787256bf5f55909dc0c398e49b5c9808,af88277c5d4abdc0a3f56f416011966d04a3f462
"""
    accounts_dan = """127.0.0.1 : 9999  : dan : 1cc2efa77d8833d83556e0cc4fa617c64eebc7fb,c1a50281fc43e860fe78c16c73b9618ada59f959
"""

    @classmethod
    def write_homedir_file(cls, name, content):
        if not name or not content:
            return
        with open(os.path.join(cls.homedir, name), "w") as f:
            f.write(content)

    @classmethod
    def setUpClass(cls):
        super(PyzorTestBase, cls).setUpClass()
        try:
            os.mkdir(cls.homedir)
        except OSError:
            pass

        cls.write_homedir_file(cls.access_file, cls.access)
        cls.write_homedir_file(cls.password_file, cls.passwd)
        cls.write_homedir_file(cls.password_file, cls.passwd)

        cls.write_homedir_file("servers", cls.servers)
        cls.write_homedir_file("alice", cls.accounts_alice)
        cls.write_homedir_file("bob", cls.accounts_bob)
        cls.write_homedir_file("chuck", cls.accounts_chuck)
        cls.write_homedir_file("dan", cls.accounts_dan)

        args = ["pyzord"]
        for key, value in cls._args.iteritems():
            option = getattr(cls, key, None)
            if option:
                args.append(value)
                args.append(option)
        cls.pyzord = []

        for line in cls.servers.splitlines():
            line = line.strip()
            if not line:
                continue
            addr, port = line.rsplit(":", 1)
            cls.pyzord.append(subprocess.Popen(args + ["-a", addr, "-p", port]))
        time.sleep(1)  # allow time to initialize server

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.client_args = {"--homedir": self.homedir,
                            "--servers-file": "servers",
                            "-t": None,  # timeout
                            "-r": None,  # report threshold
                            "-w": None,  # whitelist threshold
                            "-s": None,  # style
                            }

    def tearDown(self):
        unittest.TestCase.tearDown(self)

    @classmethod
    def tearDownClass(cls):
        super(PyzorTestBase, cls).tearDownClass()
        for pyzord in cls.pyzord:
            pyzord.terminate()
            pyzord.wait()
        shutil.rmtree(cls.homedir, True)
        redis.StrictRedis(db=10).flushdb()

    def check_pyzor(self, cmd, user, input=None,
                    code=None, exit_code=None, counts=()):
        """Call the pyzor client with the specified args from self.client_args
        and verifies the response.
        """
        args = ["pyzor"]
        if user:
            args.append("--accounts-file")
            args.append(user)
        for key, value in self.client_args.iteritems():
            if value:
                args.append(key)
                args.append(value)
        args.append(cmd)
        pyzor = subprocess.Popen(args,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        if input:
            stdout, stderr = pyzor.communicate(input.encode("utf8"))
        else:
            stdout, stderr = pyzor.communicate()

        if stderr:
            self.fail(stderr)
        if code is not None:
            try:
                stdout = stdout.decode("utf8")
                results = stdout.strip().split("\t")
                status = eval(results[1])
            except Exception as e:
                self.fail("Parsing error: %s of %r" % (e, stdout))
            self.assertEqual(status[0], code, status)

            if counts:
                self.assertEqual(counts, (int(results[2]), int(results[3])))

        if exit_code is not None:
            self.assertEqual(exit_code, pyzor.returncode)
        return stdout

    def check_pyzor_multiple(self, cmd, user, input=None,
                             code=None, exit_code=None, counts=()):
        """Call the pyzor client with the specified args from self.client_args
        and verifies the response.
        """
        args = ["pyzor"]
        if user:
            args.append("--accounts-file")
            args.append(user)
        for key, value in self.client_args.iteritems():
            if value:
                args.append(key)
                args.append(value)
        args.append(cmd)
        pyzor = subprocess.Popen(args,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        if input:
            stdout, stderr = pyzor.communicate(input.encode("utf8"))
        else:
            stdout, stderr = pyzor.communicate()

        if stderr:
            self.fail(stderr)

        stdout = stdout.decode("utf8")
        for i, line in enumerate(stdout.splitlines()):
            try:
                line = line.strip()
                if not line:
                    continue
                results = line.strip().split("\t")
            except Exception as e:
                self.fail("Parsing error: %s of %r" % (e, stdout))
            if code is not None:
                try:
                    status = eval(results[1])
                except Exception as e:
                    self.fail("Parsing error: %s of %r" % (e, stdout))
                self.assertEqual(status[0], code[i], status)
            if counts:
                self.assertEqual((int(results[2]), int(results[3])),
                                 counts[i])

        if exit_code is not None:
            self.assertEqual(exit_code, pyzor.returncode)
        return stdout

    def check_digest(self, digest, address, counts=(0, 0)):
        result = self.client.check(digest, address)

        self.assertEqual((int(result["Count"]), int(result["WL-Count"])),
                          counts)
        return result

    def get_record(self, input, user="bob"):
        """Uses `pyzor info` to get the record data."""
        stdout = self.check_pyzor("info", user, input, code=200, exit_code=0)
        info = stdout.splitlines()[1:]
        record = {}
        try:
            for line in info:
                line = line.strip()
                if not line:
                    continue
                key, value = line.split(":", 1)
                record[key.strip()] = value.strip()
        except Exception as e:
            self.fail("Error parsing %r: %s" % (info, e))
        return record

    def check_fuzzy_date(self, date1, date2=None, seconds=5):
        """Check if the given date is almost equal to now."""
        date1 = _dt_decode(date1)
        if not date2:
            date2 = datetime.now()
        delta = abs((date2 - date1).total_seconds())
        if delta > seconds:
            self.fail("Delta %s is too big: %s, %s" % (delta , date1, date2))

class PyzorTest(object):
    """MixIn class for PyzorTestBase that performs a series of basic tests."""
    def test_ping(self):
        self.check_pyzor("ping", "bob")

    def test_pong(self):
        input = "Test1 pong1 Test2"
        self.check_pyzor("pong", "bob", input=input, code=200, exit_code=0,
                         counts=(sys.maxint, 0))

    def test_check(self):
        input = "Test1 check1 Test2"
        self.check_pyzor("check", "bob", input=input, code=200, exit_code=1,
                         counts=(0, 0))
        r = self.get_record(input)
        self.assertEqual(r["Count"], "0")

    def test_report(self):
        input = "Test1 report1 Test2"
        self.check_pyzor("report", "bob", input=input, code=200, exit_code=0)
        self.check_pyzor("check", "bob", input=input, code=200, exit_code=0,
                         counts=(1, 0))
        r = self.get_record(input)
        self.assertEqual(r["Count"], "1")
        self.check_fuzzy_date(r["Entered"])

    def test_report_update(self):
        input = "Test1 report update1 Test2"
        self.check_pyzor("report", "bob", input=input, code=200, exit_code=0)
        self.check_pyzor("check", "bob", input=input, code=200, exit_code=0,
                         counts=(1, 0))
        time.sleep(1)
        self.check_pyzor("report", "bob", input=input, code=200, exit_code=0)
        self.check_pyzor("check", "bob", input=input, code=200, exit_code=0,
                         counts=(2, 0))
        r = self.get_record(input)
        self.assertEqual(r["Count"], "2")
        self.assertNotEqual(r["Entered"], r["Updated"])
        self.check_fuzzy_date(r["Updated"])

    def test_whitelist(self):
        input = "Test1 white list1 Test2"
        self.check_pyzor("whitelist", "bob", input=input, code=200, exit_code=0)
        self.check_pyzor("check", "bob", input=input, code=200, exit_code=1,
                         counts=(0, 1))
        r = self.get_record(input)
        self.assertEqual(r["WL-Count"], "1")
        self.check_fuzzy_date(r["WL-Entered"])

    def test_whitelist_update(self):
        input = "Test1 white list update1 Test2"
        self.check_pyzor("whitelist", "bob", input=input, code=200, exit_code=0)
        self.check_pyzor("check", "bob", input=input, code=200, exit_code=1,
                         counts=(0, 1))
        time.sleep(1)
        self.check_pyzor("whitelist", "bob", input=input, code=200, exit_code=0)
        self.check_pyzor("check", "bob", input=input, code=200, exit_code=1,
                         counts=(0, 2))
        r = self.get_record(input)
        self.assertEqual(r["WL-Count"], "2")
        self.assertNotEqual(r["WL-Entered"], r["WL-Updated"])
        self.check_fuzzy_date(r["WL-Updated"])

    def test_report_whitelist(self):
        input = "Test1 white list report1 Test2"
        self.check_pyzor("whitelist", "bob", input=input, code=200, exit_code=0)
        self.check_pyzor("report", "bob", input=input, code=200, exit_code=0)
        self.check_pyzor("check", "bob", input=input, code=200, exit_code=1,
                         counts=(1, 1))
        r = self.get_record(input)
        self.assertEqual(r["Count"], "1")
        self.check_fuzzy_date(r["Entered"])
        self.assertEqual(r["WL-Count"], "1")
        self.check_fuzzy_date(r["WL-Entered"])

    def test_report_whitelist_update(self):
        input = "Test1 white list report update1 Test2"
        self.check_pyzor("whitelist", "bob", input=input, code=200, exit_code=0)
        self.check_pyzor("report", "bob", input=input, code=200, exit_code=0)
        self.check_pyzor("check", "bob", input=input, code=200, exit_code=1,
                         counts=(1, 1))
        time.sleep(1)
        self.check_pyzor("whitelist", "bob", input=input, code=200, exit_code=0)
        self.check_pyzor("report", "bob", input=input, code=200, exit_code=0)
        self.check_pyzor("check", "bob", input=input, code=200, exit_code=1,
                         counts=(2, 2))
        r = self.get_record(input)
        self.assertEqual(r["Count"], "2")
        self.assertNotEqual(r["Entered"], r["Updated"])
        self.check_fuzzy_date(r["Updated"])

        self.assertEqual(r["WL-Count"], "2")
        self.assertNotEqual(r["WL-Entered"], r["WL-Updated"])
        self.check_fuzzy_date(r["WL-Updated"])

