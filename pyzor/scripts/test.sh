#!/bin/sh

# HOME so it finds the right .pyzor
export HOME=.
export PYTHONPATH=../lib
port=9999
db='test.db'

fail()
{
    [ ${server_pid:-0} != 0 ] && kill $server_pid
    echo "failed"
    exit 1;
}

setcount()
{
  count=`./pyzor check < test.in.0 | cut -d : -f 2 | cut -d ' ' -f 2`
}

rm -f $db
./pyzord -d $db $port 2>/dev/null &
server_pid=$!

# time to grab the socket
sleep 1

setcount
[ ${count:--1} = 0 ] || fail

./pyzor report < test.in.0 || fail
./pyzor report < test.in.0 || fail

setcount
[ ${count:--1} = 2 ] || fail

./pyzor report --mbox < test.in.mbox || fail
setcount
[ ${count:--1} = 3 ] || fail

./pyzor ping || fail

kill $server_pid
echo "passed"
