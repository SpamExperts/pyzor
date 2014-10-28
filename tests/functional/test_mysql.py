import unittest
import ConfigParser

from tests.util import *

try:
    import MySQLdb
    has_mysql = True
except ImportError:
    has_mysql = False

schema = """
    CREATE TABLE IF NOT EXISTS `%s` (
    `digest` char(40) default NULL,
    `r_count` int(11) default NULL,
    `wl_count` int(11) default NULL,
    `r_entered` datetime default NULL,
    `wl_entered` datetime default NULL,
    `r_updated` datetime default NULL,
    `wl_updated` datetime default NULL,
    PRIMARY KEY  (`digest`)
    )
"""

@unittest.skipIf(not os.path.exists("./test.conf"),
                 "test.conf is not available")
@unittest.skipIf(not has_mysql, "MySQLdb library not available")
class MySQLdbPyzorTest(PyzorTest, PyzorTestBase):
    """Test the mysql engine."""
    dsn = None
    engine = "mysql"

    @classmethod
    def setUpClass(cls):
        conf = ConfigParser.ConfigParser()    
        conf.read("./test.conf")
        table = conf.get("test", "table")        
        db = MySQLdb.Connect(host=conf.get("test", "host"),
                             user=conf.get("test", "user"),
                             passwd=conf.get("test", "passwd"),
                             db=conf.get("test", "db")) 
        c = db.cursor()
        c.execute(schema % table)
        c.close()
        db.close()
        cls.dsn = "%s,%s,%s,%s,%s" % (conf.get("test", "host"),
                                      conf.get("test", "user"),
                                      conf.get("test", "passwd"),
                                      conf.get("test", "db"),
                                      conf.get("test", "table"))
        super(MySQLdbPyzorTest, cls).setUpClass()
        
    @classmethod
    def tearDownClass(cls):
        super(MySQLdbPyzorTest, cls).tearDownClass()
        try:
            conf = ConfigParser.ConfigParser()    
            conf.read("./test.conf")
            table = conf.get("test", "table")        
            db = MySQLdb.Connect(host=conf.get("test", "host"),
                                 user=conf.get("test", "user"),
                                 passwd=conf.get("test", "passwd"),
                                 db=conf.get("test", "db"))
            c = db.cursor()
            c.execute("DROP TABLE %s" % table)
            c.close()
            db.close()
        except:
            pass


class ThreadsMySQLdbPyzorTest(MySQLdbPyzorTest):
    """Test the mysql engine with threads activated."""
    threads = "True"
    max_threads = "0"


class BoundedThreadsMySQLdbPyzorTest(MySQLdbPyzorTest):
    """Test the mysql engine with threads and DBConnections set."""
    threads = "True"
    max_threads = "0"
    db_connections = "10"


class MaxThreadsMySQLdbPyzorTest(MySQLdbPyzorTest):
    """Test the mysql engine with threads and MaxThreads set."""
    threads = "True"
    max_threads = "10"


class BoundedMaxThreadsMySQLdbPyzorTest(MySQLdbPyzorTest):
    """Test the mysql engine with threads, MaxThreads and DBConnections set."""
    threads = "True"
    max_threads = "10"
    db_connections = "10"


class ProcessesMySQLdbPyzorTest(MySQLdbPyzorTest):
    processes = "True"
    max_processes = "10"


class PreForkMySQLdbPyzorTest(MySQLdbPyzorTest):
    prefork = "4"


def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(MySQLdbPyzorTest))
    test_suite.addTest(unittest.makeSuite(ThreadsMySQLdbPyzorTest))
    test_suite.addTest(unittest.makeSuite(BoundedThreadsMySQLdbPyzorTest))
    test_suite.addTest(unittest.makeSuite(MaxThreadsMySQLdbPyzorTest))
    test_suite.addTest(unittest.makeSuite(BoundedMaxThreadsMySQLdbPyzorTest))
    test_suite.addTest(unittest.makeSuite(ProcessesMySQLdbPyzorTest))
    test_suite.addTest(unittest.makeSuite(PreForkMySQLdbPyzorTest))
    return test_suite
        
if __name__ == '__main__':
    unittest.main()
