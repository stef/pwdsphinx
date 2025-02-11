#!/usr/bin/env python3

import sys, base64, pysodium, binascii

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

def convert(rwd, user, host, *opts):
    seed=rwd[:32]
    kid=rwd[32:40]
    pk,sk=pysodium.crypto_sign_seed_keypair(seed)

    raw = (binascii.unhexlify("456400004232") +
           b'\x00' * 48 +
           kid +
           sk +
           b'\x00' * 32)
    return f"untrusted comment: minisign encrypted secret key\n{base64.b64encode(raw).decode('utf8')}"

schema = {'minisig': convert}
