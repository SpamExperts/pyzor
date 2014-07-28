from __future__ import division

import json
import Queue
import timeit
import optparse
import threading
import collections


DIGEST = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

SETUP = """
import pyzor
import string
import random
import hashlib
import pyzor.client
digest = "".join(random.choice(string.letters) for _ in xrange(50))
digest = hashlib.sha1(digest).hexdigest()
client = pyzor.client.Client(timeout=%f)
"""

CMD = """
try:
    client.%s(digest, address=(%r, %s))
except pyzor.TimeoutError:
    pass
"""

ALL_METHODS = ("pong", "check", "report", "info", "whitelist")


def measure_method(method, repeats, timeout, server, queue):
    setup = SETUP % timeout
    cmd = CMD % ((method,) + server)
    results = timeit.repeat(stmt=cmd, setup=setup, repeat=repeats, number=1)
    timeouts = sum(1 for result in results if result >= timeout)
    queue.put((method, results, timeouts))


def measure_methods(methods, repeats, timeout, server, queue):
    if methods == "all":
        methods = ALL_METHODS
    else:
        methods = methods.split(",")

    threads = []
    for method in methods:
        thread = threading.Thread(target=measure_method,
                                  args=(method, repeats, timeout, server,
                                        queue))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()


def json_handler(res):
    fres = {}
    for method, result in res.iteritems():
        fres[method] = {"runs": [],
                        "timeouts": result["timeouts"],
                        "totals": {}}
        total = 0
        best_all = []
        for i, results in enumerate(result["results"]):
            results.sort()
            average = sum(results) / len(results)
            best = results[:3]

            total += average
            best_all.extend(best)

            fres[method]["runs"].append({"average": average,
                                         "best": best})
        fres[method]["totals"]["average"] = total / len(result["results"])
        fres[method]["totals"]["best"] = best_all[:3]
    print json.dumps(fres, indent=4)


def print_handler(res):
    for method, result in res.iteritems():
        print "=" * 80
        print "Method: %s" % method
        print "Timeouts: %s" % result["timeouts"]
        print "=" * 80

        total = 0
        best_all = []
        for i, results in enumerate(result["results"]):
            results.sort()
            average = sum(results) / len(results)
            best = results[:3]

            total += average
            best_all.extend(best)

            print "\t(%s) %s %s" % (i, average, best)
        print "=" * 80
        print "Total: %s %s" % (total / len(result["results"]), best_all[:3])
        print "\n"


def main():
    opt = optparse.OptionParser()
    opt.add_option("-n", "--nice", dest="nice", type="int",
                   help="'nice' level", default=0)
    opt.add_option("-s", "--server", dest="server", default="127.0.0.1:24441")
    opt.add_option("-m", "--method", dest="method", default="all")
    opt.add_option("-f", "--format", dest="format", default="print")
    opt.add_option("-t", "--threads", dest="threads", type="int", default=1)
    opt.add_option("--timeout", dest="timeout", type="float", default=5.0)
    opt.add_option("-r", "--repeats", dest="repeats", type="int", default=1000)

    options, args = opt.parse_args()

    server = tuple(options.server.rsplit(":", 1))

    queue = Queue.Queue()

    threads = []
    for dummy in xrange(options.threads):
        thread = threading.Thread(target=measure_methods,
                                  args=(options.method, options.repeats,
                                        options.timeout, server, queue))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    def get_new_info():
        return {"results": [],
                "timeouts": 0}

    res = collections.defaultdict(get_new_info)
    while True:
        try:
            method, results, timeouts = queue.get_nowait()
            res[method]["results"].append(results)
            res[method]["timeouts"] += timeouts
        except Queue.Empty:
            break

    globals()["%s_handler" % options.format](res)


if __name__ == '__main__':
    main()
