#!/usr/bin/env python3

CREATE   =b'\x00' # sphinx
READ     =b'\x33' # blob
UNDO     =b'\x55' # change sphinx
GET      =b'\x66' # sphinx
COMMIT   =b'\x99' # change sphinx
CHANGE   =b'\xaa' # sphinx
DELETE   =b'\xff' # sphinx+blobs

CHALLENGE_CREATE = b'\x5a'
CHALLENGE_VERIFY = b'\xa5'

VERSION = b'\x00'

RULE_SIZE = 79

