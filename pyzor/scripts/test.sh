#!/bin/sh

# HOME so it finds the right .pyzor
export HOME=.
export PYTHONPATH=../lib

start_server()
{
    ./pyzord --homedir . > pyzord.log &
    PYZORD_PID=$!
    echo "started server with pid $PYZORD_PID"
}


pyzor()
{
    ./pyzor --homedir . "$@"
}


pyzor_bob()
{
    pyzor --homedir bob "$@"
}


check()
{
    pyzor check < test.in.0
}


check_bob()
{
    pyzor_bob check < test.in.0
}



kill_server()
{
    echo "killing server (pid $PYZORD_PID)"
    kill $PYZORD_PID
}

fail()
{
    echo "failed: $1"
    exit 1;
}

setcount()
{
    count=`pyzor check < test.in.0 | cut -f 3`
}

setcount_bob()
{
    count=`pyzor_bob check < test.in.0 | cut -f 3`
}

fail_cmp()
{
    fail "got $1; expected $2"
}

rm -f pyzord.*

echo "starting server"
start_server

# sleep to give it time to start listening
sleep 2

[ ! -z $PYZORD_PID ] || fail "we didn't get a process id for the server!"
kill -0 $PYZORD_PID || fail "process is dead"

trap kill_server 0

echo "anonymous: pinging"
pyzor ping || fail

echo "anonymous: ensuring a count of 0 at start"
setcount
[ ${count:--1} = 0 ] || fail
check && fail


echo "bob: ensuring a count of 0 at start"
setcount_bob
[ ${count:--1} = 0 ] || fail
check_bob && fail


echo "anonymous: reporting"
pyzor report < test.in.0 && fail
echo "anonymous: reporting"
pyzor report < test.in.0 && fail


echo "bob: reporting"
pyzor_bob report < test.in.0 || fail
echo "bob: reporting"
pyzor_bob report < test.in.0 || fail


echo "anonymous: counting reports"
setcount
[ ${count:--1} = 2 ] || fail
check || fail


echo "bob: counting reports"
setcount_bob
[ ${count:--1} = 2 ] || fail_cmp ${count:--1} 2
check_bob || fail "checking failed"


echo "bob: reporting a mailbox"
pyzor_bob report --mbox < test.in.mbox || fail


echo "bob: counting reports"
setcount_bob
[ ${count:--1} = 3 ] || fail_cmp ${count:--1} 3
check_bob || fail "checking exit code failed"


echo "bob: getting info"
# check exit
pyzor_bob info < test.in.0 || fail
# check lines
[ `pyzor_bob info < test.in.0 | wc -l` = 7 ] || fail


echo "anonymous: whitelisting"
pyzor whitelist < test.in.0 && fail

echo "bob: whitelisting"
pyzor_bob whitelist < test.in.0 || fail


echo "bob: getting info"
# check exit
pyzor_bob info < test.in.0 || fail
# check lines
[ `pyzor_bob info < test.in.0 | wc -l` = 7 ] || fail


echo "bob: counting reports"
setcount_bob
[ ${count:--1} = 0 ] || fail_cmp ${count:--1} 0
check && fail


echo "checking for logfile"
[ -s pyzord.log ] || fail

echo "passed"
