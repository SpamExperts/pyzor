#!/bin/sh

# HOME so it finds the right .pyzor
export HOME=.
export PYTHONPATH=../lib
PYZOR="./pyzor -c config"
PYZORD="./pyzord -c config"
alias check="$PYZOR check < test.in.0"

fail()
{
    kill `cat .pyzor/pyzord.pid`
    echo "failed"
    exit 1;
}

setcount()
{
  count=`$PYZOR check < test.in.0 | cut -f 2`
}

rm -rf .pyzor

echo "starting server"
$PYZORD || fail

setcount
echo "ensuring a count of 0 at start"
[ ${count:--1} = 0 ] || fail
check && fail

echo "reporting"
$PYZOR report < test.in.0 || fail
echo "reporting"
$PYZOR report < test.in.0 || fail

setcount
echo "counting reports"
[ ${count:--1} = 2 ] || fail
check || fail

echo "reporting a mailbox"
$PYZOR report --mbox < test.in.mbox || fail
setcount
echo "counting reports"
[ ${count:--1} = 3 ] || fail
check || fail

echo "pinging"
$PYZOR ping || fail

echo "checking for logfile"
[ -s .pyzor/pyzord.log ] || fail

echo "killing server"
kill `cat .pyzor/pyzord.pid` || fail

echo "passed"
