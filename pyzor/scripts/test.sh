#!/bin/sh

# HOME so it finds the right .pyzor
export HOME=.
export PYTHONPATH=../lib
PYZOR="./pyzor --homedir ."
PYZOR_BOB="./pyzor --homedir bob"
PYZORD="./pyzord --homedir ."
alias check="$PYZOR check < test.in.0"
alias check.bob="$PYZOR check < test.in.0"

kill_server()
{
  echo "killing server"
  pidfile='pyzord.pid'
  [ -e $pidfile ] && kill `cat $pidfile`
}


fail()
{
    echo "failed: $1"
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

fail_cmp()
{
  fail "got $1; expected $2"
}

rm -f pyzord.*

echo "starting server"
$PYZORD || fail


echo "anonymous: ensuring a count of 0 at start"
setcount
[ ${count:--1} = 0 ] || fail
check && fail


echo "bob: ensuring a count of 0 at start"
setcount_bob
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


echo "anonymous: counting reports"
setcount
[ ${count:--1} = 2 ] || fail
check || fail


echo "bob: counting reports"
setcount_bob
[ ${count:--1} = 2 ] || fail_cmp ${count:--1} 2
check.bob || fail "checking failed"


echo "bob: reporting a mailbox"
$PYZOR_BOB report --mbox < test.in.mbox || fail


echo "bob: counting reports"
setcount_bob
[ ${count:--1} = 3 ] || fail_cmp ${count:--1} 3
check.bob || fail "checking exit code failed"


echo "bob: getting info"
# check exit
$PYZOR_BOB info < test.in.0 || fail
# check lines
[ `$PYZOR_BOB info < test.in.0 | wc -l` = 7 ] || fail


echo "anonymous: whitelisting"
$PYZOR whitelist < test.in.0 && fail

echo "bob: whitelisting"
$PYZOR_BOB whitelist < test.in.0 || fail


echo "bob: getting info"
# check exit
$PYZOR_BOB info < test.in.0 || fail
# check lines
[ `$PYZOR_BOB info < test.in.0 | wc -l` = 7 ] || fail


echo "bob: counting reports"
setcount_bob
[ ${count:--1} = 0 ] || fail_cmp ${count:--1} 0
check && fail


echo "anonymous: pinging"
$PYZOR ping || fail

echo "checking for logfile"
[ -s pyzord.log ] || fail

echo "anonymous: shutting down server"
$PYZOR shutdown 127.0.0.1:9999 && fail

echo "bob: shutting down server"
$PYZOR_BOB shutdown 127.0.0.1:9999 || fail

echo "passed"
