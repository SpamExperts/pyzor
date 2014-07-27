"""The the pyzor.digest module
"""

import unittest

import pyzor.digest
from pyzor.digest import *

try:
    from unittest.mock import patch, Mock, call
except ImportError:
    from mock import patch, Mock, call

HTML_TEXT = """<html><head><title>Email spam</title></head><body>
<p><b>Email spam</b>, also known as <b>junk email</b> 
or <b>unsolicited bulk email</b> (<i>UBE</i>), is a subset of 
<a href="/wiki/Spam_(electronic)" title="Spam (electronic)">electronic spam</a> 
involving nearly identical messages sent to numerous recipients by <a href="/wiki/Email" title="Email">
email</a>. Clicking on <a href="/wiki/Html_email#Security_vulnerabilities" title="Html email" class="mw-redirect">
links in spam email</a> may send users to <a href="/wiki/Phishing" title="Phishing">phishing</a> 
web sites or sites that are hosting <a href="/wiki/Malware" title="Malware">malware</a>.</body></html>"""

HTML_TEXT_STRIPED = 'Email spam Email spam , also known as junk email or unsolicited bulk email ( UBE ),' \
                    ' is a subset of electronic spam involving nearly identical messages sent to numerous recipients by email' \
                    ' . Clicking on links in spam email may send users to phishing web sites or sites that are hosting malware .'



class HTMLStripperTests(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.data = []

    def tearDown(self):
        unittest.TestCase.tearDown(self)

    def test_HTMLStripper(self):
        stripper = HTMLStripper(self.data)
        stripper.feed(HTML_TEXT)
        res = " ".join(self.data)
        self.assertEqual(res, HTML_TEXT_STRIPED)


class PreDigestTests(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.lines = []

        def mock_digest_paylods(c, message):
            yield message.decode("utf8")

        def mock_handle_line(s, line):
            self.lines.append(line.decode("utf8"))

        self.real_digest_payloads = DataDigester.digest_payloads
        self.real_handle_line = DataDigester.handle_line
        DataDigester.digest_payloads = mock_digest_paylods
        DataDigester.handle_line = mock_handle_line

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        DataDigester.digest_payloads = self.real_digest_payloads
        DataDigester.handle_line = self.real_handle_line


    def test_predigest_emails(self):
        """Test email removal in the predigest process"""
        real_longstr = DataDigester.longstr_ptrn
        DataDigester.longstr_ptrn = re.compile(r'\S{100,}')
        emails = ["test@example.com",
                  "test123@example.com",
                  "test+abc@example.com",
                  "test.test2@example.com",
                  "test.test2+abc@example.com", ]
        message = "Test %s Test2"
        expected = "TestTest2"
        try:
            for email in emails:
                self.lines = []
                DataDigester((message % email).encode("utf8"))
                self.assertEqual(self.lines[0], expected)
        finally:
            DataDigester.longstr_ptrn = real_longstr

    def test_predigest_urls(self):
        """Test url removal in the predigest process"""
        real_longstr = DataDigester.longstr_ptrn
        DataDigester.longstr_ptrn = re.compile(r'\S{100,}')
        urls = ["http://www.example.com",
                # "www.example.com", # XXX This also fail
                "http://example.com",
                # "example.com", # XXX This also fails
                "http://www.example.com/test/"
                "http://www.example.com/test/test2", ]
        message = "Test %s Test2"
        expected = "TestTest2"
        try:
            for url in urls:
                self.lines = []
                DataDigester((message % url).encode("utf8"))
                self.assertEqual(self.lines[0], expected)
        finally:
            DataDigester.longstr_ptrn = real_longstr

    def test_predigest_long(self):
        """Test long "words" removal in the predigest process"""
        strings = ["0A2D3f%a#S",
                   "3sddkf9jdkd9",
                   "@@#@@@@@@@@@"]
        message = "Test %s Test2"
        expected = "TestTest2"
        for string in strings:
            self.lines = []
            DataDigester((message % string).encode("utf8"))
            self.assertEqual(self.lines[0], expected)

    def test_predigest_min_line_lenght(self):
        """Test small lines removal in the predigest process"""
        message = "This line is included\n" \
                  "not this\n" \
                  "This also"
        expected = ["Thislineisincluded", "Thisalso"]
        DataDigester(message.encode("utf8"))
        self.assertEqual(self.lines, expected)

    def test_predigest_atomic(self):
        """Test atomic messages (lines <= 4) in the predigest process"""
        message = "All this message\nShould be included\nIn the predigest"
        expected = ["Allthismessage", "Shouldbeincluded", "Inthepredigest"]
        DataDigester(message.encode("utf8"))
        self.assertEqual(self.lines, expected)

    def test_predigest_pieced(self):
        """Test pieced messages (lines > 4) in the predigest process"""
        message = ""
        for i in range(100):
            message += "Line%d test test test\n" % i
        expected = []
        for i in [20, 21, 22, 60, 61, 62]:
            expected.append("Line%dtesttesttest" % i)
        DataDigester(message.encode("utf8"))
        self.assertEqual(self.lines, expected)


class DigestTests(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.lines = []

        def mock_digest_paylods(c, message):
            yield message.decode("utf8")

        self.real_digest_payloads = DataDigester.digest_payloads
        DataDigester.digest_payloads = mock_digest_paylods

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        DataDigester.digest_payloads = self.real_digest_payloads

    def test_digest(self):
        message = b"That's some good ham right there"
        predigested = b"That'ssomegoodhamrightthere"

        digest = hashlib.sha1()
        digest.update(predigested)

        expected = digest.hexdigest()
        result = DataDigester(message).value

        self.assertEqual(result, expected)


class MessageDigest(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        patch("pyzor.digest.DataDigester.normalize_html_part",
              return_value="normalized").start()
        self.config = {
            "get_content_maintype.return_value": "text",
            "get_content_charset.return_value": "utf8",
            "get_payload.return_value": Mock(),
            "get_payload.return_value.decode.return_value": "decoded"
        }

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def check_msg(self):
        mock_part = Mock(**self.config)
        conf = {"walk.return_value": [mock_part]}
        mock_msg = Mock(**conf)
        return mock_part, mock_msg, list(DataDigester.digest_payloads(mock_msg))

    def test_text(self):
        mock_part, mock_msg, result = self.check_msg()
        self.assertEqual(result, ["decoded"])

        expected = [call.decode('utf8', 'ignore')]
        payload = mock_part.get_payload.return_value
        payload.assert_has_calls(expected, True)

    def test_text_no_charset(self):
        self.config["get_content_charset.return_value"] = None
        mock_part, mock_msg, result = self.check_msg()
        self.assertEqual(result, ["decoded"])

        expected = [call.decode('ascii', 'ignore')]
        payload = mock_part.get_payload.return_value
        payload.assert_has_calls(expected)

    def test_text_quopri(self):
        self.config["get_content_charset.return_value"] = "quopri"
        mock_part, mock_msg, result = self.check_msg()
        self.assertEqual(result, ["decoded"])

        expected = [call.decode('quopri', 'strict')]
        payload = mock_part.get_payload.return_value
        payload.assert_has_calls(expected)

    def test_text_lookuperror(self):
        def _decode(encoding, errors):
            if encoding not in ("ascii",):
                raise LookupError()
            return "decoded"
        self.config["get_payload.return_value.decode.side_effect"] = _decode
        mock_part, mock_msg, result = self.check_msg()
        self.assertEqual(result, ["decoded"])

        expected = [call.decode('utf8', 'ignore'),
                    call.decode('ascii', 'ignore')]
        payload = mock_part.get_payload.return_value
        payload.assert_has_calls(expected)

    def test_text_unicodeerror(self):
        self.config["get_payload.return_value.decode.side_effect"] = UnicodeError
        mock_part, mock_msg, result = self.check_msg()
        self.assertEqual(result, [])

        expected = [call.decode('utf8', 'ignore'),
                    call.decode('ascii', 'ignore')]
        payload = mock_part.get_payload.return_value
        payload.assert_has_calls(expected)

    def test_html(self):
        self.config["get_content_subtype.return_value"] = "html"
        mock_part, mock_msg, result = self.check_msg()
        self.assertEqual(result, ["normalized"])

    def test_multipart(self):
        self.config["get_content_maintype.return_value"] = "nottext"
        self.config["is_multipart.return_value"] = True
        mock_part, mock_msg, result = self.check_msg()
        self.assertEqual(result, [])

    def test_nontext(self):
        self.config["get_content_maintype.return_value"] = "nottext"
        self.config["is_multipart.return_value"] = False
        mock_part, mock_msg, result = self.check_msg()
        self.assertEqual(result, [mock_part.get_payload.return_value])


def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(HTMLStripperTests))
    test_suite.addTest(unittest.makeSuite(PreDigestTests))
    test_suite.addTest(unittest.makeSuite(DigestTests))
    return test_suite


if __name__ == '__main__':
    unittest.main()

