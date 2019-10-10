#!/bin/bash -e

hash() {
   md5sum | { read md5 rest; echo $md5; }
}

[[ -d data ]] || {
   echo no data directory found
   echo please start ../pwdsphinx/oracle.py
   exit 1
}
[[ -f data/salt ]] && {
   echo data directory is not fresh
   echo please delete it and restart oracle:
   echo "rm -rf data ; ../pwdsphinx/oracle.py"
   exit 1
}
echo "create user1"
echo "asdf" | ../pwdsphinx/sphinx.py create user1 example.com ulsd 80 | read rwd0
echo "get user1 rwd"
echo "asdf" | ../pwdsphinx/sphinx.py get user1 example.com | read rwd
[[ "$rwd" == "$rwd0" ]] || false
echo "change user1 rwd"
echo "asdf" | ../pwdsphinx/sphinx.py change user1 example.com | read rwd1
echo "get user1 rwd"
echo "asdf" | ../pwdsphinx/sphinx.py get user1 example.com | read rwd
[[ "$rwd" == "$rwd0" ]] || false
echo "commit user1 changed rwd"
echo "asdf" | ../pwdsphinx/sphinx.py commit user1 example.com | read rwd
[[ "$rwd" == "$rwd1" ]] || false
rwd0="$rwd1"
echo "commit user1 changed rwd again - fail"
echo "asdf" | ../pwdsphinx/sphinx.py commit user1 example.com || true
echo "get user1 rwd"
echo "asdf" | ../pwdsphinx/sphinx.py get user1 example.com | read rwd
[[ "$rwd" == "$rwd0" ]] || false
echo "create user2 rwd"
echo "asdf" | ../pwdsphinx/sphinx.py create user2 example.com ulsd 80 | read rwds0
echo "get user2 rwd"
echo "asdf" | ../pwdsphinx/sphinx.py get user2 example.com | read rwds
[[ "$rwds" == "$rwds0" ]] || false
echo "list users rwd"
md5=$(echo "asdf" | ../pwdsphinx/sphinx.py list example.com | hash)
[[ "$md5" == "57c246efc4d56f6210462408b5f8ef2e" ]]
echo "delete user2 rwd"
echo "asdf" | ../pwdsphinx/sphinx.py delete user2 example.com
echo "list users rwd"
md5=$(echo "asdf" | ../pwdsphinx/sphinx.py list example.com | hash)
[[ "$md5" == "a609316768619f154ef58db4d847b75e" ]]
echo "asdf" | ../pwdsphinx/sphinx.py get user2 example.com || true
echo "all tests passed"
