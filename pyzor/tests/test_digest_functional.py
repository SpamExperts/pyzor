import sys
import hashlib
import unittest

from util import *

TEXT = """MIME-Version: 1.0
Sender: chirila@spamexperts.com
Received: by 10.216.90.129 with HTTP; Fri, 23 Aug 2013 01:59:03 -0700 (PDT)
Date: Fri, 23 Aug 2013 11:59:03 +0300
Delivered-To: chirila@spamexperts.com
X-Google-Sender-Auth: p6ay4c-tEtdFpavndA9KBmP0CVs
Message-ID: <CAK-mJS9aV6Kb7Z5XCRJ_z_UOKEaQjRY8gMzsuxUQcN5iqxNWUg@mail.gmail.com>
Subject: Test
From: Alexandru Chirila <chirila@spamexperts.com>
To: Alexandru Chirila <chirila@spamexperts.com>
Content-Type: multipart/alternative; boundary=001a11c2893246a9e604e4999ea3

--001a11c2893246a9e604e4999ea3
Content-Type: text/plain; charset=ISO-8859-1

%s

--001a11c2893246a9e604e4999ea3
"""

HTML_TEXT = """MIME-Version: 1.0
Sender: chirila@gapps.spamexperts.com
Received: by 10.216.157.70 with HTTP; Thu, 16 Jan 2014 00:43:31 -0800 (PST)
Date: Thu, 16 Jan 2014 10:43:31 +0200
Delivered-To: chirila@gapps.spamexperts.com
X-Google-Sender-Auth: ybCmONS9U9D6ZUfjx-9_tY-hF2Q
Message-ID: <CAK-mJS8sE-V6qtspzzZ+bZ1eSUE_FNMt3K-5kBOG-z3NMgU_Rg@mail.gmail.com>
Subject: Test
From: Alexandru Chirila <chirila@spamexperts.com>
To: Alexandru Chirila <chirila@gapps.spamexperts.com>
Content-Type: multipart/alternative; boundary=001a11c25ff293069304f0126bfd

--001a11c25ff293069304f0126bfd
Content-Type: text/plain; charset=ISO-8859-1

Email spam.

Email spam, also known as junk email or unsolicited bulk email, is a subset
of electronic spam involving nearly identical messages sent to numerous
recipients by email. Clicking on links in spam email may send users to
phishing web sites or sites that are hosting malware.

--001a11c25ff293069304f0126bfd
Content-Type: text/html; charset=ISO-8859-1
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div>Email spam.</div><div><br></div><div>Email spam, also=
 known as junk email or unsolicited bulk email, is a subset of electronic s=
pam involving nearly identical messages sent to numerous recipients by emai=
l. Clicking on links in spam email may send users to phishing web sites or =
sites that are hosting malware.</div>
</div>

--001a11c25ff293069304f0126bfd--
"""

class PyzorPreDigestTest(PyzorTestBase):
    # we don't need the pyzord server to test this 
    @classmethod
    def setUpClass(cls):
        pass
    @classmethod
    def tearDownClass(cls):
        pass
    def setUp(self):
        # no argument necessary
        self.client_args = {}

    def test_predigest_email(self):
        """Test email removal in the predigest process"""
        emails = ["t@abc.ro",
                  "t1@abc.ro",
                  "t+@abc.ro",
                  "t.@abc.ro",
                  ]
        message = "Test %s Test2"
        expected = "TestTest2\n"
        for email in emails:
            msg = message % email
            res = self.check_pyzor("predigest", None, input=TEXT % msg)
            self.assertEqual(res, expected)
    
    def test_predigest_long(self):
        """Test long "words" removal in the predigest process"""
        strings = ["0A2D3f%a#S",
                   "3sddkf9jdkd9",
                   "@@#@@@@@@@@@"]
        message = "Test %s Test2"
        expected = "TestTest2\n"
        for s in strings:
            msg = message % s
            res = self.check_pyzor("predigest", None, input=TEXT % msg)
            self.assertEqual(res, expected)
    
    def test_predigest_line_length(self):
        """Test small lines removal in the predigest process"""
        msg = "This line is included\n"\
              "not this\n"\
              "This also"
        expected = "Thislineisincluded\nThisalso\n"
        res = self.check_pyzor("predigest", None, input=TEXT % msg)
        self.assertEqual(res, expected)
        
    def test_predigest_atomic(self):
        """Test atomic messages (lines <= 4) in the predigest process"""
        msg = "All this message\nShould be included\nIn the predigest"
        expected = "Allthismessage\nShouldbeincluded\nInthepredigest\n"
        res = self.check_pyzor("predigest", None, input=TEXT % msg)
        self.assertEqual(res, expected)
    
    def test_predigest_pieced(self):
        """Test pieced messages (lines > 4) in the predigest process"""
        msg = ""
        for i in range(100):
            msg += "Line%d test test test\n" % i
        expected = ""
        for i in [20, 21, 22, 60, 61, 62]:
            expected += "Line%dtesttesttest\n" % i
        res = self.check_pyzor("predigest", None, input=TEXT % msg)
        self.assertEqual(res, expected)

    def test_predigest_html(self):
        expected = """Emailspam,alsoknownasjunkemailorbulkemail,isasubset
ofspaminvolvingnearlyidenticalmessagessenttonumerous
byemail.Clickingonlinksinspamemailmaysendusersto
byemail.Clickingonlinksinspamemailmaysendusersto
phishingwebsitesorsitesthatarehostingmalware.
Emailspam.Emailspam,alsoknownasjunkemailorbulkemail,isasubsetofspaminvolvingnearlyidenticalmessagessenttonumerousbyemail.Clickingonlinksinspamemailmaysenduserstophishingwebsitesorsitesthatarehostingmalware.
"""
        res = self.check_pyzor("predigest", None, input=HTML_TEXT)
        self.assertEqual(res, expected)
        
class PyzorDigestTest(PyzorTestBase):
    # we don't need the pyzord server to test this 
    @classmethod
    def setUpClass(cls):
        pass
    @classmethod
    def tearDownClass(cls):
        pass
    def setUp(self):
        # no argument necessary
        self.client_args = {}

    def test_digest_email(self):
        """Test email removal in the digest process"""
        emails = ["t@abc.ro",
                  "t1@abc.ro",
                  "t+@abc.ro",
                  "t.@abc.ro",
                  ]
        message = "Test %s Test2"
        expected = "TestTest2"
        for email in emails:
            msg = message % email
            res = self.check_pyzor("digest", None, input=TEXT % msg)
            self.assertEqual(res, hashlib.sha1(expected).hexdigest().lower() + "\n")
    
    def test_digest_long(self):
        """Test long "words" removal in the digest process"""
        strings = ["0A2D3f%a#S",
                   "3sddkf9jdkd9",
                   "@@#@@@@@@@@@"]
        message = "Test %s Test2"
        expected = "TestTest2"
        for s in strings:
            msg = message % s
            res = self.check_pyzor("digest", None, input=TEXT % msg)
            self.assertEqual(res, hashlib.sha1(expected).hexdigest().lower() + "\n")
    
    def test_digest_line_length(self):
        """Test small lines removal in the digest process"""
        msg = "This line is included\n"\
              "not this\n"\
              "This also"
        expected = "ThislineisincludedThisalso"
        res = self.check_pyzor("digest", None, input=TEXT % msg)
        self.assertEqual(res, hashlib.sha1(expected).hexdigest().lower() + "\n")
        
    def test_digest_atomic(self):
        """Test atomic messages (lines <= 4) in the digest process"""
        msg = "All this message\nShould be included\nIn the digest"
        expected = "AllthismessageShouldbeincludedInthedigest"
        res = self.check_pyzor("digest", None, input=TEXT % msg)
        self.assertEqual(res, hashlib.sha1(expected).hexdigest().lower() + "\n")
    
    def test_digest_pieced(self):
        """Test pieced messages (lines > 4) in the digest process"""
        msg = ""
        for i in range(100):
            msg += "Line%d test test test\n" % i
        expected = ""
        for i in [20, 21, 22, 60, 61, 62]:
            expected += "Line%dtesttesttest" % i
        res = self.check_pyzor("digest", None, input=TEXT % msg)
        self.assertEqual(res, hashlib.sha1(expected).hexdigest().lower() + "\n")

    def test_digest_html(self):
        expected = """Emailspam,alsoknownasjunkemailorbulkemail,isasubset
ofspaminvolvingnearlyidenticalmessagessenttonumerous
byemail.Clickingonlinksinspamemailmaysendusersto
byemail.Clickingonlinksinspamemailmaysendusersto
phishingwebsitesorsitesthatarehostingmalware.
Emailspam.Emailspam,alsoknownasjunkemailorbulkemail,isasubsetofspaminvolvingnearlyidenticalmessagessenttonumerousbyemail.Clickingonlinksinspamemailmaysenduserstophishingwebsitesorsitesthatarehostingmalware.
""".replace("\n", "")
        res = self.check_pyzor("digest", None, input=HTML_TEXT)
        self.assertEqual(res, hashlib.sha1(expected).hexdigest().lower() + "\n")

def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(PyzorDigestTest))
    test_suite.addTest(unittest.makeSuite(PyzorPreDigestTest))    
    return test_suite
        
if __name__ == '__main__':
    unittest.main()
        
        
        
        
        
        
        
        
        
        
        
        
        
        