#!/bin/sh

export HOME=.
port=9999
db='test.db'

fail()
{
    echo "failed"
    [ ${server_pid:-0} ] && kill $server_pid
    exit 1;
}

rm -f $db
./pyzord -d $db $port 2>/dev/null &
server_pid=$!

# time to grab the socket
sleep 1

./pyzor report < test.in.0 || fail
./pyzor report < test.in.0 || fail
[ `./pyzor check < test.in.0` = 2 ] || fail
./pyzor ping || fail

kill $server_pid
