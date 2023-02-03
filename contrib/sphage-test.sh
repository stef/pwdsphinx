#!/bin/sh

set -e

pubkey=$(echo "asdf" | sha256sum | cut -d' ' -f 1 | rax2 -s | python3 sphage.py pubkey)
privkey=$(mktemp)
echo "asdf" | sha256sum | cut -d' ' -f 1 | rax2 -s | python3 sphage.py privkey >"$privkey"
echo "hello world" | age -r $pubkey | age --decrypt -i "$privkey"

rm -rf "$privkey"
