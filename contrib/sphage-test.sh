#!/bin/sh

set -e

# simulate output from sphinx
rwd=$(echo "asdf" | sha256sum | cut -d' ' -f 1 | rax2 -s)

# convert rwd to age "identity" (privkey)
privkey=$(mktemp)
echo "$rwd" | python3 sphage privkey >"$privkey"

# convert rwd to age "recipient" (pubkey)
pubkey=$(echo -n "$rwd" | python3 sphage pubkey)

# encrypt and decrypt hello world using the above key pair derived from rwd
echo "hello world" | age -r $pubkey | age --decrypt -i "$privkey"

# clean up
rm -rf "$privkey"
