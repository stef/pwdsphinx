#!/usr/bin/env python

from base64 import b32decode
import hmac
from struct import pack, unpack
import sys
from time import time

def totp(key, *opts, time_step=30, digits=6, digest='sha1'):
    if isinstance(key, bytes): key=key.decode('utf8')
    key = b32decode(key.upper() + '=' * ((8 - len(key)) % 8))
    ts = pack('>Q', int(time() / time_step))
    mac = hmac.new(key, ts, digest).digest()
    offset = mac[-1] & 0x0f
    binary = unpack('>L', mac[offset:offset+4])[0] & 0x7fffffff
    return str(binary)[-digits:].zfill(digits)

schema = {"otp": totp}

def main():
    args = [int(x) if x.isdigit() else x for x in sys.argv[1:]]
    for key in sys.stdin:
        print(totp(key.strip(), [], *args))

if __name__ == '__main__':
    main()
