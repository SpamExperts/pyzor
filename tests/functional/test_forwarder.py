import sys
import unittest
import random

import time

import pyzor.forwarder

if __name__ == '__main__':
    sys.path.insert(0,'..')
from util import *

class ForwardSetup(object):
    """Setup forwarding client and 'remote' pyzord"""

    def write_homedir_file(self,name, content):
        if not name or not content:
            return
        with open(os.path.join(self.homedir, name), "w") as f:
            f.write(content)

    def __init__(self,homedir):
        self.homedir=homedir
        try:
            os.mkdir(homedir)
        except OSError:
            pass

class ForwarderTest(unittest.TestCase):

    def setUp(self):
        self.localserver = ForwardSetup('./pyzor-test-forwardserver') # we also use this dir for the local client
        self.localserver.write_homedir_file('servers', '127.0.0.1:9999\n')

        self.fwdclient = ForwardSetup('./pyzor-test-forwardingclient')
        self.fwdclient.write_homedir_file('servers','127.0.0.1:9998\n')

        args = ["pyzord","--homedir",self.localserver.homedir,'-a','127.0.0.1','-p','9999','--forward-client-homedir',self.fwdclient.homedir]
        self.local_pyzord_proc = subprocess.Popen(args)

        self.remoteserver = ForwardSetup('./pyzor-test-remoteserver')
        args = ["pyzord","--homedir",self.remoteserver.homedir,'-a','127.0.0.1','-p','9998']
        self.remote_pyzord_proc = subprocess.Popen(args)
        time.sleep(0.3)

    def test_forward_report(self):
        #submit hash to local server
        self.check_pyzor("report", self.localserver.homedir)

        #make sure the local submission worked
        self.check_pyzor("check",  self.localserver.homedir,counts=(1, 0),msg='local insert failed')

        #now use the forwarding client's config to check forwarded submission
        time.sleep(1)
        self.check_pyzor("check", self.fwdclient.homedir, counts=(1, 0),msg='forwarding failed')

        #submit the hash to the remote system, the count should go up
        self.check_pyzor("report", self.fwdclient.homedir)
        self.check_pyzor("check", self.fwdclient.homedir, counts=(2, 0), msg='submit to remote failed')

        #switch back to our local server, the count should still be the old value
        self.check_pyzor("check", self.localserver.homedir, counts=(1, 0), msg='local count is wrong')

    def tearDown(self):
        if self.remote_pyzord_proc!=None:
            self.remote_pyzord_proc.kill()
        if self.local_pyzord_proc!=None:
            self.local_pyzord_proc.kill()

        shutil.rmtree(self.localserver.homedir, True)
        shutil.rmtree(self.fwdclient.homedir, True)
        shutil.rmtree(self.remoteserver.homedir, True)

    def check_pyzor(self, cmd, homedir, counts=None,msg=None):
        """simplified check_pyzor version from PyzorTestBase"""
        input="forwarding makes the world go round!"
        args = ["pyzor",'--homedir',homedir,cmd]
        pyzor = subprocess.Popen(args,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

        stdout, stderr = pyzor.communicate(input.encode("utf8"))

        if stderr:
            self.fail(stderr)

        try:
            stdout = stdout.decode("utf8")
            results = stdout.strip().split("\t")
            status = eval(results[1])
        except Exception as e:
            import traceback
            print traceback.format_exc()
            self.fail("Parsing error: %s of %r" % (e, stdout))
        self.assertEqual(status[0], 200, status)

        if counts:
            self.assertEqual(counts, (int(results[2]), int(results[3])),msg)
        return stdout

def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(ForwarderTest))
    return test_suite

if __name__ == '__main__':
    unittest.main()
