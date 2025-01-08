#!/usr/bin/env python3

CREATE      =b'\x00' # sphinx
READ        =b'\x33' # blob
UNDO        =b'\x55' # change sphinx
GET         =b'\x66' # sphinx
V1GET       =b'\x69' # v1 sphinx
COMMIT      =b'\x99' # change sphinx
CHANGE_DKG  =b'\xa0' # sphinx/dkg
CHANGE      =b'\xaa' # sphinx
CREATE_DKG  =b'\xf0' # sphinx/dkg
V1DELETE    =b'\xf9' # v1 sphinx+blobs
DELETE      =b'\xff' # sphinx+blobs

CHALLENGE_CREATE = b'\x5a'
CHALLENGE_VERIFY = b'\xa5'

VERSION = b'\x01'

V1RULE_SIZE = 79
RULE_SIZE = V1RULE_SIZE+32
