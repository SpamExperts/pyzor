#!/bin/sh

# HOME so it finds the right .pyzor
export HOME=.
export PYTHONPATH=../lib
PYZOR="./pyzor -c config"
PYZOR_BOB="./pyzor -c config.bob"
PYZORD="./pyzord -c config"
alias check="$PYZOR check < test.in.0"
alias check.bob="$PYZOR check < test.in.0"

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

setcount_bob()
{
  count=`$PYZOR check < test.in.0 | cut -f 3`
}

rm -rf .pyzor

echo "starting server"
$PYZORD || fail

setcount
echo "anonymous: ensuring a count of 0 at start"
[ ${count:--1} = 0 ] || fail
check && fail

setcount_bob
echo "bob: ensuring a count of 0 at start"
[ ${count:--1} = 0 ] || fail
check.bob && fail

echo "anonymous: reporting"
$PYZOR report < test.in.0 && fail
echo "anonymous: reporting"
$PYZOR report < test.in.0 && fail

echo "bob: reporting"
$PYZOR_BOB report < test.in.0 || fail
echo "bob: reporting"
$PYZOR_BOB report < test.in.0 || fail

setcount
echo "anonymous: counting reports"
[ ${count:--1} = 2 ] || fail
check || fail

setcount_bob
echo "bob: counting reports"
[ ${count:--1} = 2 ] || fail
check.bob || fail

echo "bob: reporting a mailbox"
$PYZOR_BOB report --mbox < test.in.mbox || fail

echo "bob: getting info"
# check exit
$PYZOR_BOB info < test.in.0 || fail
# check lines
[ `$PYZOR_BOB info < test.in.0 | wc -l` = 4 ] || fail

setcount_bob
echo "bob: counting reports"
[ ${count:--1} = 3 ] || fail
check.bob || fail

echo "anonymous: pinging"
$PYZOR ping || fail

echo "checking for logfile"
[ -s .pyzor/pyzord.log ] || fail

echo "anonymous: shutting down server"
$PYZOR shutdown 127.0.0.1:9999 && fail

echo "bob: shutting down server"
$PYZOR_BOB shutdown 127.0.0.1:9999 || fail

echo "passed"
