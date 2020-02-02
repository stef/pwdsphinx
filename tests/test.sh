#!/bin/bash -e

hash() {
   md5sum | { read md5 rest; echo $md5; }
}

[[ -d data ]] || {
   echo no data directory found
   echo please start ../pwdsphinx/oracle.py
   exit 1
}
echo "create user1"
rwd0="$(echo -n 'asdf' | ../pwdsphinx/sphinx.py create user1 example.com ulsd 80)"
echo "get user1 rwd"
rwd="$(echo -n 'asdf' | ../pwdsphinx/sphinx.py get user1 example.com)"
[[ "$rwd" == "$rwd0" ]] || false
echo "change user1 rwd"
rwd1="$(echo -n 'asdf' | ../pwdsphinx/sphinx.py change user1 example.com)"
echo "get user1 rwd"
rwd="$(echo -n 'asdf' | ../pwdsphinx/sphinx.py get user1 example.com)"
[[ "$rwd" == "$rwd0" ]] || false
echo "commit user1 changed rwd"
rwd="$(echo -n 'asdf' | ../pwdsphinx/sphinx.py commit user1 example.com)"
[[ "$rwd" == "$rwd1" ]] || false
echo "undo user1"
rwd="$(echo -n 'asdf' | ./sphinx.py undo user1 example.com)"
[[ "$rwd" == "$rwd0" ]] || false
echo "commit again user1 changed rwd"
rwd="$(echo -n 'asdf' | ../pwdsphinx/sphinx.py commit user1 example.com)"
[[ "$rwd" == "$rwd1" ]] || false
rwd0="$rwd1"
echo "commit user1 changed rwd again - fail"
echo -n 'asdf' | ../pwdsphinx/sphinx.py commit user1 example.com || true
echo "get user1 rwd"
rwd="$(echo -n 'asdf' | ../pwdsphinx/sphinx.py get user1 example.com)"
[[ "$rwd" == "$rwd0" ]] || false

echo "write an arbitary blob"
blob0="some secret string"
echo -ne "asdf\n$blob0" | ../pwdsphinx/sphinx.py write user1 example.com
echo "read block back"
blob="$(echo -n 'asdf' | ../pwdsphinx/sphinx.py read user1 example.com)"
[[ "${blob}"=="${blob0}" ]] || false
echo "overwrite the blob"
blob1="another secret string"
echo -ne "asdf\n$blob1" | ../pwdsphinx/sphinx.py write user1 example.com
echo "read overwritten block back"
blob="$(echo -n 'asdf' | ../pwdsphinx/sphinx.py read user1 example.com)"
[[ "${blob}"=="${blob1}" ]] || false

echo "create user2 rwd"
rwds0="$(echo -n 'asdf' | ../pwdsphinx/sphinx.py create user2 example.com ulsd 80)"
echo "get user2 rwd"
rwds="$(echo -n 'asdf' | ../pwdsphinx/sphinx.py get user2 example.com)"
[[ "$rwds" == "$rwds0" ]] || false
echo "list users rwd"
md5="$(echo -n 'asdf' | ../pwdsphinx/sphinx.py list example.com | hash)"
[[ "$md5" == "57c246efc4d56f6210462408b5f8ef2e" ]]
echo "delete user2 rwd"
echo -n 'asdf' | ../pwdsphinx/sphinx.py delete user2 example.com
echo "list users rwd"
md5="$(echo -n 'asdf' | ../pwdsphinx/sphinx.py list example.com | hash)"
[[ "$md5" == "a609316768619f154ef58db4d847b75e" ]]
echo "get user2 rwd - fail"
echo -n 'asdf' | ../pwdsphinx/sphinx.py get user2 example.com || true

echo "all tests passed"
