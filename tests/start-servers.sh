#!/bin/sh

cleanup() {
 echo killing oracles $server1 $server2 $server3 $server4 $server5
 kill $server1 $server2 $server3 $server4 $server5
 exit
}

cd servers/0; ../../../pwdsphinx/oracle.py &
server1=$!
sleep 0.1

cd ../../servers/1; ../../../pwdsphinx/oracle.py &
server2=$!
sleep 0.1

cd ../../servers/2; ../../../pwdsphinx/oracle.py &
server3=$!
sleep 0.1

cd ../../servers/3; ../../../pwdsphinx/oracle.py &
server4=$!
sleep 0.1

cd ../../servers/4; ../../../pwdsphinx/oracle.py &
server5=$!
sleep 0.1

trap "cleanup" INT
while true; do sleep 1 ;done
