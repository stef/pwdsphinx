#!/usr/bin/env python3

import sys, base64, pysodium, binascii, struct
from pwdsphinx.consts import *

# usage
# create key and save pubkey
# getpwd | env/bin/sphinx create ssh-ed25519://test asdf | pipe2tmpfile ssh-keygen -e -f @@keyfile@@ >pubkey
# sign file
# getpwd | env/bin/sphinx get ssh-ed25519://test asdf | pipe2tmpfile ssh-keygen -Y sign -n file -f @@keyfile@@ content.txt > content.txt.sig
# verify file with pubkey
# ssh-keygen -Y check-novalidate -n file -f /tmp/ssh-ed.pubkey -s /tmp/content.txt.sig </tmp/content.txt

from itertools import zip_longest # for Python 3.x
def split_by_n(iterable, n):
    return zip_longest(*[iter(iterable)]*n, fillvalue='')

def privkey(rwd, user, host):
    seed=rwd[:32]
    pk,sk=pysodium.crypto_sign_seed_keypair(seed)

    comment = f"{user}@{host}".encode('utf8')
    comment = struct.pack(">I", len(comment)) + comment

    secrethalf = (
           binascii.unhexlify("a2224bbaa2224bba"               # iv/salt? (Not sure about these 8 bytes)
                              # Here's a repeat of the public key (part of the private key pair)
                              "0000000b"                       # int length = 11
                              "7373682d65643235353139"         # string key type = ssh-ed25519
                              "00000020") +                    # int length = 32
                              # public key payload 32 bytes
                              # probably encoding a point on the ed25519 curve
           pk +
           binascii.unhexlify("00000040") +                    # int length = 64
           # 32 bytes private key payload 1
           sk +                                                # really sk[32] + pk[32]
           comment)                                            # int length + comment as string
    # padding 3 bytes incrementing integers, pads to blocksize 8, starts with "remaining payload"
    padding = bytes(i+1 for i in range(-len(secrethalf)%8))
    secrethalf = secrethalf + padding
    assert len(secrethalf) % 8 == 0

    raw = (binascii.unhexlify("6f70656e7373682d6b65792d763100" # ASCII magic "openssh-key-v1" plus null byte
                              "00000004"                       # int length = 4
                              "6e6f6e65"                       #string cipher = none
                              "00000004"                       # int length = 4
                              "6e6f6e65"                       # string kdfname = none
                              "00000000"                       # int length = 0
                              # zero-length kdfoptions placeholder here
                              "00000001"                       # int number of public keys = 1
                              "00000033"                       # int length first public key = 51 (4 + 11 + 4 + 32)
                              "0000000b"                       # int length = 11
                              "7373682d65643235353139"         # string key type = ssh-ed25519
                              "00000020") +                    # int length = 32
           # public key payload 32 bytes
           # probably encoding a point on the ed25519 curve
           pk +
           struct.pack(">I", len(secrethalf)) +                # int length = 144 size of remaining payload
                                                               # 8 + 4 + 11 + 4 + 32 + 4 + 64 + 4 + {10 + 3}
           secrethalf)

    return ("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            '\n'.join(''.join(l) for l in split_by_n(base64.b64encode(raw).decode('utf8'), 70)) +
            "\n-----END OPENSSH PRIVATE KEY-----")

def pubkey(rwd, user, host):
    seed=rwd[:32]
    pk,sk=pysodium.crypto_sign_seed_keypair(seed)

    raw = (binascii.unhexlify("0000000b"                       # int length = 11
                              "7373682d65643235353139"         # string key type = ssh-ed25519
                              "00000020") +                    # int length = 32
           pk)

    return f"ssh-ed25519 {base64.b64encode(raw).decode('utf8')} {user}@{host}"

def convert(rwd, user, host, op, *opts):
    if op in {CREATE, CHANGE}:
        return pubkey(rwd, user, host)
    return privkey(rwd,user, host)

schema = {'ssh-ed25519': convert}
