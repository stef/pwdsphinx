#!/bin/sh

ORACLE=${ORACLE:-../../../pwdsphinx/oracle.py}
PIDS=""

cleanup() {
 echo killing oracles ${PIDS}
 kill ${PIDS}
 exit
}

start_server() {
   printf "starting %s %s\n" "$ORACLE" "$1"
   cd "servers/$1"
   "$ORACLE" >log 2>&1 &
   PIDS="$PIDS $!"
   sleep 0.1
   cd - >/dev/null
}

start_server 0
start_server 1
start_server 2
start_server 3
start_server 4

trap "cleanup" INT
while true; do sleep 1 ;done
