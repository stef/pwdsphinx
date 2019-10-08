"""Wrapper for libsphinx library

   Copyright (c) 2018, Marsiske Stefan.
   All rights reserved.

   This file is part of pitchforked sphinx.

   pitchforked sphinx is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of
   the License, or (at your option) any later version.

   pitchforked sphinx is distributed in the hope that it will be
   useful, but WITHOUT ANY WARRANTY; without even the implied
   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with pitchforked sphinx. If not, see <http://www.gnu.org/licenses/>.
"""

import ctypes
import ctypes.util

sphinxlib = ctypes.cdll.LoadLibrary(ctypes.util.find_library('sphinx') or ctypes.util.find_library('libsphinx'))

if not sphinxlib._name:
    raise ValueError('Unable to find libsphinx')

DECAF_255_SCALAR_BYTES = 32
DECAF_255_SER_BYTES    = 32

def __check(code):
    if code != 0:
        raise ValueError

# void challenge(const uint8_t *pwd, const size_t p_len, uint8_t *bfac, uint8_t *chal)
def challenge(pwd):
    if pwd == None:
        raise ValueError("invalid parameter")
    bfac = ctypes.create_string_buffer(DECAF_255_SCALAR_BYTES)
    chal = ctypes.create_string_buffer(DECAF_255_SER_BYTES)
    sphinxlib.sphinx_challenge(pwd, len(pwd), bfac, chal)
    return (bfac.raw, chal.raw)

# int respond(const uint8_t *chal, const uint8_t *secret, uint8_t *resp)
def respond(chal, secret):
    if None in (chal, secret):
        raise ValueError("invalid parameter")
    if len(chal) != DECAF_255_SER_BYTES: raise ValueError("truncated point")
    if len(secret) != DECAF_255_SCALAR_BYTES: raise ValueError("truncated secret")

    resp = ctypes.create_string_buffer(DECAF_255_SER_BYTES)

    __check(sphinxlib.sphinx_respond(chal, secret, resp))
    return resp.raw

# int finish(const uint8_t *pwd, const size_t p_len, const uint8_t *bfac, const uint8_t *resp, uint8_t *rwd)
def finish(pwd, bfac, resp):
    if None in (pwd, bfac, resp):
        raise ValueError("invalid parameter")
    if len(resp) != DECAF_255_SER_BYTES: raise ValueError("truncated point")
    if len(bfac) != DECAF_255_SCALAR_BYTES: raise ValueError("truncated secret")

    rwd = ctypes.create_string_buffer(DECAF_255_SER_BYTES)
    __check(sphinxlib.sphinx_finish(pwd, len(pwd), bfac, resp, rwd))
    return rwd.raw

from pysodium import crypto_secretbox_MACBYTES, crypto_secretbox_NONCEBYTES

DECAF_255_SCALAR_BYTES = 32
DECAF_X25519_PRIVATE_BYTES = 32
DECAF_X25519_PUBLIC_BYTES = 32

OPAQUE_BLOB_LEN = (crypto_secretbox_NONCEBYTES+DECAF_X25519_PRIVATE_BYTES+DECAF_X25519_PUBLIC_BYTES+DECAF_X25519_PUBLIC_BYTES+crypto_secretbox_MACBYTES)
OPAQUE_USER_RECORD_LEN = (DECAF_255_SCALAR_BYTES+DECAF_X25519_PRIVATE_BYTES+DECAF_X25519_PUBLIC_BYTES+DECAF_X25519_PUBLIC_BYTES+32+8+OPAQUE_BLOB_LEN)
OPAQUE_USER_SESSION_PUBLIC_LEN = (DECAF_X25519_PUBLIC_BYTES+DECAF_X25519_PUBLIC_BYTES)
OPAQUE_USER_SESSION_SECRET_LEN = (DECAF_X25519_PRIVATE_BYTES+DECAF_X25519_PRIVATE_BYTES)
OPAQUE_SERVER_SESSION_LEN = (DECAF_X25519_PUBLIC_BYTES+DECAF_X25519_PUBLIC_BYTES+32+8+OPAQUE_BLOB_LEN)
OPAQUE_REGISTER_PUBLIC_LEN = (DECAF_X25519_PUBLIC_BYTES+DECAF_X25519_PUBLIC_BYTES)
OPAQUE_REGISTER_SECRET_LEN = (DECAF_X25519_PRIVATE_BYTES+DECAF_X25519_PRIVATE_BYTES)

# This function implements the same function from the paper. This
# function runs on the server and creates a new output record rec of
# secret key material partly encrypted with a key derived from the
# input password pw. The server needs to implement the storage of
# this record and any binding to user names or as the paper suggests
# sid.
# int opaque_storePwdFile(const uint8_t *pw, const ssize_t pwlen, const unsigned char *extra, const uint64_t extra_len, unsigned char rec[OPAQUE_USER_RECORD_LEN]);
def opaque_store(pwd, extra = None):
    if not pwd:
        raise ValueError("invalid parameter")

    rec = ctypes.create_string_buffer(OPAQUE_USER_RECORD_LEN+(len(extra) if extra is not None else 0))
    extra_len = ctypes.c_ulonglong(len(extra)) if extra is not None else ctypes.c_ulonglong(0)
    __check(sphinxlib.opaque_storePwdFile(pwd, len(pwd), extra, extra_len, rec))
    return rec.raw

# This function initiates a new OPAQUE session, is the same as the
# function defined in the paper with the same name. The User initiates
# a new session by providing its input password pw, and receving a
# private sec and a "public" pub output parameter. The User should
# protect the sec value until later in the protocol and send the pub
# value over to the Server.
# void opaque_usrSession(const uint8_t *pw, const ssize_t pwlen, unsigned char sec[OPAQUE_USER_SESSION_SECRET_LEN], unsigned char pub[OPAQUE_USER_SESSION_PUBLIC_LEN]);
def opaque_usrSession(pwd):
    if not pwd:
        raise ValueError("invalid parameter")
    sec = ctypes.create_string_buffer(OPAQUE_USER_SESSION_SECRET_LEN)
    pub = ctypes.create_string_buffer(OPAQUE_USER_SESSION_PUBLIC_LEN)
    sphinxlib.opaque_usrSession(pwd, len(pwd), sec, pub)
    return pub.raw, sec.raw

# This is the same function as defined in the paper with the same
# name. It runs on the server and receives the output pub from the
# user running usrSession(), futhermore the server needs to load the
# user record created when registering the user with the
# storePwdFile() function. These input parameters are transformed into
# a secret/shared session key sk and a response resp to be sent back
# to the user.
# int opaque_srvSession(const unsigned char pub[OPAQUE_USER_SESSION_PUBLIC_LEN], const unsigned char rec[OPAQUE_USER_RECORD_LEN], unsigned char resp[OPAQUE_SERVER_SESSION_LEN], uint8_t *sk);
def opaque_srvSession(pub, rec):
    if None in (pub, rec):
        raise ValueError("invalid parameter")
    if len(pub) != OPAQUE_USER_SESSION_PUBLIC_LEN: raise ValueError("invalid pub param")
    if len(rec) < OPAQUE_USER_RECORD_LEN: raise ValueError("invalid rec param")

    resp = ctypes.create_string_buffer(OPAQUE_SERVER_SESSION_LEN + (len(rec) - OPAQUE_USER_RECORD_LEN))
    sk = ctypes.create_string_buffer(32)
    __check(sphinxlib.opaque_srvSession(pub, rec, resp, sk))
    return resp.raw, sk.raw

# This is the same function as defined in the paper with the same
# name. It is run by the user, and recieves as input the response from
# the previous server srvSession() function as well as the sec value
# from running the usrSession() function that initiated this protocol,
# the user password pw is also needed as an input to this final
# step. All these input parameters are transformed into a shared/secret
# session key pk, which should be the same as the one calculated by the
# srvSession() function.
# int opaque_usrSessionEnd(const uint8_t *pw, const ssize_t pwlen, const unsigned char resp[OPAQUE_SERVER_SESSION_LEN], const unsigned char sec[OPAQUE_USER_SESSION_SECRET_LEN], uint8_t *sk, uint8_t *extra)
def opaque_usrSessionEnd(pwd, resp, sec):
    if None in (pwd, resp, sec):
        raise ValueError("invalid parameter")
    if len(resp) < OPAQUE_SERVER_SESSION_LEN: raise ValueError("invalid resp param")
    if len(sec) != OPAQUE_USER_SESSION_SECRET_LEN: raise ValueError("invalid sec param")

    sk = ctypes.create_string_buffer(32)
    extra = ctypes.create_string_buffer(len(resp) - OPAQUE_SERVER_SESSION_LEN)
    __check(sphinxlib.opaque_usrSessionEnd(pwd, len(pwd), resp, sec, sk, extra))
    return sk.raw, extra.raw

# This is a simple utility function that can be used to calculate
# f_k(c), where c is a constant, this is useful if the peers want to
# authenticate each other.
# void opaque_f(const uint8_t *k, const size_t k_len, const uint8_t val, uint8_t *res);
def opaque_f(k, val):
    if None in (k, val):
        raise ValueError("invalid parameter")

    res = ctypes.create_string_buffer(32)
    v = ctypes.c_uint8(val)
    sphinxlib.opaque_f(k, len(k), v, res)
    return res.raw

# Alternative user initialization
#
# The paper originally proposes a very simple 1 shot interface for
# registering a new "user", however this has the drawback that in
# that case the users secrets and its password are exposed in
# cleartext at registration to the server. There is a much less
# efficient 4 message registration protocol which avoids the exposure
# of the secrets and the password to the server which can be
# instantiated by the following for registration functions:

# The user inputs its password pw, and receives an ephemeral secret r
# and a blinded value alpha as output. r should be protected until
# step 3 of this registration protocol and the value alpha should be
# passed to the server.
# void opaque_newUser(const uint8_t *pw, const ssize_t pwlen, uint8_t *r, uint8_t *alpha);
def opaque_newUser(pwd):
    if not pwd:
        raise ValueError("invalid parameter")

    r = ctypes.create_string_buffer(32)
    alpha = ctypes.create_string_buffer(32)
    sphinxlib.opaque_newUser(pwd, len(pwd), r, alpha)
    return r.raw, alpha.raw

# The server receives alpha from the users invocation of its
# newUser() function, it outputs a value sec which needs to be
# protected until step 4 by the server. This function also outputs a
# value pub which needs to be passed to the user.
# int opaque_initUser(const uint8_t *alpha, unsigned char sec[OPAQUE_REGISTER_SECRET_LEN], unsigned char pub[OPAQUE_REGISTER_PUBLIC_LEN]);
def opaque_initUser(alpha):
    if not alpha:
        raise ValueError("invalid parameter")
    if len(alpha) != 32: raise ValueError("invalid alpha param")

    sec = ctypes.create_string_buffer(OPAQUE_REGISTER_SECRET_LEN)
    pub = ctypes.create_string_buffer(OPAQUE_REGISTER_PUBLIC_LEN)
    __check(sphinxlib.opaque_initUser(alpha, sec, pub))
    return sec.raw, pub.raw

# This function is run by the user, taking as input the users
# password pw, the ephemeral secret r that was an output of the user
# running newUser(), and the output pub from the servers run of
# initUser(). The result of this is the value rec which should be
# passed for the last step to the server.
# int opaque_registerUser(const uint8_t *pw, const ssize_t pwlen, const uint8_t *r, const unsigned char pub[OPAQUE_REGISTER_PUBLIC_LEN], const unsigned char *extra, const ssize_t extra_len, unsigned char rec[OPAQUE_USER_RECORD_LEN]);
def opaque_registerUser(pw, r, pub, extra = None):
    if None in (pw, r, pub):
        raise ValueError("invalid parameter")
    if len(r) != 32: raise ValueError("invalid r param")
    if len(pub) != OPAQUE_REGISTER_PUBLIC_LEN: raise ValueError("invalid pub param")

    rec = ctypes.create_string_buffer(OPAQUE_USER_RECORD_LEN+(len(extra) if extra is not None else 0))
    extralen = ctypes.c_ulonglong(len(extra)) if extra is not None else ctypes.c_ulonglong(0)
    __check(sphinxlib.opaque_registerUser(pw, len(pw), r, pub, extra, extralen, rec))
    return rec.raw

# The server combines the sec value from its run of its initUser()
# function with the rec output of the users registerUser() function,
# creating the final record, which should be the same as the output
# of the 1-step storePwdFile() init function of the paper. The server
# should save this record in combination with a user id and/or sid
# value as suggested in the paper.
# void opaque_saveUser(const unsigned char sec[OPAQUE_REGISTER_SECRET_LEN], const unsigned char pub[OPAQUE_REGISTER_PUBLIC_LEN], unsigned char rec[OPAQUE_USER_RECORD_LEN]);
def opaque_saveUser(sec, pub, rec):
    if None in (sec, pub, rec):
        raise ValueError("invalid parameter")
    if len(sec) != OPAQUE_REGISTER_SECRET_LEN: raise ValueError("invalid sec param")
    if len(pub) != OPAQUE_REGISTER_PUBLIC_LEN: raise ValueError("invalid pub param")
    if len(rec) < OPAQUE_USER_RECORD_LEN: raise ValueError("invalid rec param")

    sphinxlib.opaque_saveUser(sec, pub, rec)
    return rec
