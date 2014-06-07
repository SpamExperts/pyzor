#!/usr/bin/python
import pyzor
import pyzor.engines

import sys
import logging
import optparse

def get_engine(engine,dsn,mode='c'):
    engine_class=pyzor.engines.database_classes[engine].single_threaded
    engine_instance=engine_class(dsn,mode)
    return engine_instance

def migrate(opts):
    ok_count=0
    fail_count=0
    print_interval=100000
    
    source_engine=get_engine(opts.source_engine,opts.source_dsn,mode='r')
    destination_engine=get_engine(opts.destination_engine,opts.destination_dsn)
    
    it = source_engine.iteritems()
    while True:
        try:
            key, record = it.next()
            destination_engine[key]=record
            ok_count += 1
            if ok_count%print_interval == 0:
                print "%s records transferred..."%ok_count            
        except StopIteration:
            break
        except Exception,e:
            fail_count += 1
            print "Record %s failed: %s"%(key,str(e))

    print "Migration complete, %s records transferred successfully, %s records failed"%(ok_count,fail_count)

if __name__ == '__main__':
    logging.basicConfig()
    parser=optparse.OptionParser()
    
    parser.add_option("--se", "--source-engine", action="store", default=None,
                   dest="source_engine", help="select source database backend")
    parser.add_option("--sd", "--source-dsn", action="store", default=None, dest="source_dsn",
                   help="data source DSN - see pyzor documentation for format")
    parser.add_option("--de", "--destination-engine", action="store", default=None,
                   dest="destination_engine", help="select destination database backend")
    parser.add_option("--dd", "--destination-dsn", action="store", default=None, dest="destination_dsn",
                   help="destination DSN - see pyzor documentation for format")

    (opts,args)=parser.parse_args()

    if not (opts.source_engine and opts.source_dsn and opts.destination_engine and opts.destination_dsn):
        print "options --se/--sd/--de/--dd are required"
        sys.exit(1)
    
    if opts.source_engine not in pyzor.engines.database_classes:
        print "Unsupported source engine: %s"%opts.source_engine
        sys.exit(1)
        
    if opts.destination_engine not in pyzor.engines.database_classes:
        print "Unsupported destination engine: %s"%opts.destination_engine
        sys.exit(1)

    migrate(opts)
    