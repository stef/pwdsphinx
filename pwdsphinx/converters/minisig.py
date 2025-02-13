#!/usr/bin/env python3

import sys, base64, pysodium, binascii
from pwdsphinx.consts import *

# usage
# getpwd | env/bin/sphinx create minisig://test asdf | pipe2tmpfile minisign -R -s @@keyfile@@ -p /tmp/minisig.pub
# getpwd | env/bin/sphinx get minisig://test asdf | pipe2tmpfile minisign -S -s @@keyfile@@ -m filetosign

"""format is
untrusted comment: sphinx generated minisign key\n
base64(
  4564 0000 4232 <\x00 * 48>
  <keynum 8B unique key identifier>
  <secret key 32B>
  <public key 32B>
  <\x00 * 32>
)

use crypto_sign_ed25519_sk_to_pk(unsigned char *pk, const unsigned char *sk);
to derive pubkey from secret key
"""

def privkey(sk, kid):
    raw = (binascii.unhexlify("456400004232") +
           b'\x00' * 48 +
           kid +
           sk +
           b'\x00' * 32)
    return f"untrusted comment: minisign secret key\n{base64.b64encode(raw).decode('utf8')}"

def pubkey(pk, kid):
    raw = (b'Ed' + kid + pk)
    return f"untrusted comment: minisign public key\n{base64.b64encode(raw).decode('utf8')}"

def convert(rwd, user, host, op, *opts):
    seed=rwd[:32]
    kid=rwd[32:40]
    pk,sk=pysodium.crypto_sign_seed_keypair(seed)
    if op in {CREATE, CHANGE}:
        return pubkey(pk, kid)
    return privkey(sk, kid)

schema = {'minisig': convert}
