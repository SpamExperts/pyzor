#!/bin/sh

# HOME so it finds the right .pyzor
export HOME=.
export PYTHONPATH=../lib
PYZOR="./pyzor -c config"
PYZORD="./pyzord -c config"
alias check="$PYZOR check < test.in.0"

kill_server()
{
  echo "killing server"
  pidfile='.pyzor/pyzord.pid'
  [ -e $pidfile ] && kill `cat $pidfile`
}


fail()
{
    echo "failed"
    kill_server
    exit 1;
}

setcount()
{
  count=`$PYZOR check < test.in.0 | cut -f 3`
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

kill_server || fail

echo "passed"
