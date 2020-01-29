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
from pysodium import (crypto_secretbox_MACBYTES, crypto_secretbox_NONCEBYTES,
                      crypto_secretbox_KEYBYTES, crypto_scalarmult_SCALARBYTES,
                      crypto_scalarmult_BYTES, crypto_generichash_BYTES,
                      #crypto_core_ristretto255_SCALARBYTES, crypto_core_ristretto255_BYTES, # not implemented yet in pysodium
                     )

crypto_core_ristretto255_SCALARBYTES = 32
crypto_core_ristretto255_BYTES = 32

sphinxlib = ctypes.cdll.LoadLibrary(ctypes.util.find_library('sphinx') or ctypes.util.find_library('libsphinx'))

if not sphinxlib._name:
    raise ValueError('Unable to find libsphinx')

def __check(code):
    if code != 0:
        raise ValueError

#int sphinx_challenge(const uint8_t *pwd, const size_t p_len,
#                     const uint8_t *salt,const size_t salt_len,
#                     uint8_t bfac[crypto_core_ristretto255_SCALARBYTES],
#                     uint8_t chal[crypto_core_ristretto255_BYTES]);
def challenge(pwd, salt):
    if pwd == None:
        raise ValueError("invalid parameter")
    bfac = ctypes.create_string_buffer(crypto_core_ristretto255_SCALARBYTES)
    chal = ctypes.create_string_buffer(crypto_core_ristretto255_SER_BYTES)
    saltlen = ctypes.c_ulonglong(len(salt)) if salt is not None else ctypes.c_ulonglong(0)
    sphinxlib.sphinx_challenge(pwd, len(pwd), salt, saltlen, bfac, chal)
    return (bfac.raw, chal.raw)

#int sphinx_respond(const uint8_t chal[crypto_core_ristretto255_BYTES],
#                   const uint8_t secret[crypto_core_ristretto255_SCALARBYTES],
#                   uint8_t resp[crypto_core_ristretto255_BYTES]);
def respond(chal, secret):
    if None in (chal, secret):
        raise ValueError("invalid parameter")
    if len(chal) != crypto_core_ristretto255_BYTES: raise ValueError("truncated point")
    if len(secret) != crypto_core_ristretto255_SCALARBYTES: raise ValueError("truncated secret")

    resp = ctypes.create_string_buffer(crypto_core_ristretto255_BYTES)

    __check(sphinxlib.sphinx_respond(chal, secret, resp))
    return resp.raw

#int sphinx_finish(const uint8_t *pwd, const size_t p_len,
#                  const uint8_t bfac[crypto_core_ristretto255_SCALARBYTES],
#                  const uint8_t resp[crypto_core_ristretto255_BYTES],
#                  const uint8_t salt[crypto_pwhash_SALTBYTES],
#                  uint8_t rwd[crypto_core_ristretto255_BYTES]);
def finish(pwd, salt, bfac, resp):
    if None in (pwd, bfac, resp):
        raise ValueError("invalid parameter")
    if len(resp) != crypto_core_ristretto255_BYTES: raise ValueError("truncated point")
    if len(bfac) != crypto_core_ristretto255_SCALARBYTES: raise ValueError("truncated secret")

    rwd = ctypes.create_string_buffer(DECAF_255_SER_BYTES)
    __check(sphinxlib.sphinx_finish(pwd, len(pwd), bfac, resp, salt, rwd))
    return rwd.raw

OPAQUE_MAX_EXTRA_BYTES = 1024*1024 # 1 MB should be enough for even most PQ params
OPAQUE_BLOB_LEN = (crypto_secretbox_NONCEBYTES+crypto_scalarmult_SCALARBYTES+crypto_scalarmult_BYTES+crypto_scalarmult_BYTES+crypto_secretbox_MACBYTES)
OPAQUE_USER_RECORD_LEN = (crypto_core_ristretto255_SCALARBYTES+crypto_scalarmult_SCALARBYTES+crypto_scalarmult_BYTES+crypto_scalarmult_BYTES+32+8+OPAQUE_BLOB_LEN)
OPAQUE_USER_SESSION_PUBLIC_LEN = (crypto_core_ristretto255_BYTES+crypto_scalarmult_BYTES)
OPAQUE_USER_SESSION_SECRET_LEN = (crypto_core_ristretto255_SCALARBYTES+crypto_scalarmult_SCALARBYTES)
OPAQUE_SERVER_SESSION_LEN = (crypto_core_ristretto255_BYTES+crypto_scalarmult_BYTES+crypto_generichash_BYTES+32+8+OPAQUE_BLOB_LEN)
OPAQUE_REGISTER_PUBLIC_LEN = (crypto_core_ristretto255_BYTES+crypto_scalarmult_BYTES)
OPAQUE_REGISTER_SECRET_LEN = (crypto_scalarmult_SCALARBYTES+crypto_core_ristretto255_SCALARBYTES)

# This function implements the storePwdFile function from the
# paper. This function runs on the server and creates a new output
# record rec of secret key material and optional extra data partly
# encrypted with a key derived from the input password pw. The server
# needs to implement the storage of this record and any binding to
# user names or as the paper suggests sid.  *Attention* the size of
# rec depends on the size of extra data provided.
# int opaque_init_srv(const uint8_t *pw, const size_t pwlen, const uint8_t *extra, const uint64_t extra_len, const uint8_t *key, const uint64_t key_len, uint8_t rec[OPAQUE_USER_RECORD_LEN]);
def opaque_init_srv(pwd, extra = None, key = None):
    if not pwd:
        raise ValueError("invalid parameter")

    rec = ctypes.create_string_buffer(OPAQUE_USER_RECORD_LEN+(len(extra) if extra is not None else 0))
    extra_len = ctypes.c_ulonglong(len(extra)) if extra is not None else ctypes.c_ulonglong(0)
    key_len = ctypes.c_ulonglong(len(key)) if key is not None else ctypes.c_ulonglong(0)
    __check(sphinxlib.opaque_init_srv(pwd, len(pwd), extra, extra_len, key, key_len, rec))
    return rec.raw


# This function initiates a new OPAQUE session, is the same as the function
# defined in the paper with the usrSession name. The User initiates a new session by
# providing its input password pw, and receving a private sec and a "public"
# pub output parameter. The User should protect the sec value until later in
# the protocol and send the pub value over to the Server.
# int opaque_session_usr_start(const uint8_t *pw, const size_t pwlen, uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN], uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN]);
def opaque_session_usr_start(pwd):
    if not pwd:
        raise ValueError("invalid parameter")
    sec = ctypes.create_string_buffer(OPAQUE_USER_SESSION_SECRET_LEN)
    pub = ctypes.create_string_buffer(OPAQUE_USER_SESSION_PUBLIC_LEN)
    __check(sphinxlib.opaque_session_usr_start(pwd, len(pwd), sec, pub))
    return pub.raw, sec.raw


# This is the same function as defined in the paper with the srvSession name. It runs
# on the server and receives the output pub from the user running usrSession(),
# futhermore the server needs to load the user record created when registering
# the user with the storePwdFile() function. These input parameters are
# transformed into a secret/shared session key sk and a response resp to be
# sent back to the user. *Attention* rec and resp have variable length
# depending on any extra data stored.
# int opaque_session_srv(const uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN], const uint8_t rec[OPAQUE_USER_RECORD_LEN], uint8_t resp[OPAQUE_SERVER_SESSION_LEN], uint8_t *sk);
def opaque_session_srv(pub, rec):
    if None in (pub, rec):
        raise ValueError("invalid parameter")
    if len(pub) != OPAQUE_USER_SESSION_PUBLIC_LEN: raise ValueError("invalid pub param")
    if len(rec) < OPAQUE_USER_RECORD_LEN: raise ValueError("invalid rec param")

    resp = ctypes.create_string_buffer(OPAQUE_SERVER_SESSION_LEN + (len(rec) - OPAQUE_USER_RECORD_LEN))
    sk = ctypes.create_string_buffer(32)
    __check(sphinxlib.opaque_session_srv(pub, rec, resp, sk))
    return resp.raw, sk.raw


# This is the same function as defined in the paper with the usrSessionEnd name. It is
# run by the user, and recieves as input the response from the previous server
# srvSession() function as well as the sec value from running the usrSession()
# function that initiated this protocol, the user password pw is also needed as
# an input to this final step. All these input parameters are transformed into a
# shared/secret session key pk, which should be the same as the one calculated
# by the srvSession() function. *Attention* resp has a length depending on extra
# data. If rwd is not NULL it is returned - this enables to run the sphinx protocol
# in the opaque protocol.
# int opaque_session_usr_finish(const uint8_t *pw, const size_t pwlen, const uint8_t resp[OPAQUE_SERVER_SESSION_LEN], const uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN], const uint8_t *key, const uint64_t key_len, uint8_t *sk, uint8_t *extra, uint8_t rwd[crypto_secretbox_KEYBYTES]);
def opaque_session_usr_finish(pwd, resp, sec, key = None, rwd = False):
    if None in (pwd, resp, sec):
        raise ValueError("invalid parameter")
    if len(resp) < OPAQUE_SERVER_SESSION_LEN: raise ValueError("invalid resp param")
    if len(sec) != OPAQUE_USER_SESSION_SECRET_LEN: raise ValueError("invalid sec param")

    key_len = ctypes.c_ulonglong(len(key)) if key is not None else ctypes.c_ulonglong(0)

    sk = ctypes.create_string_buffer(32)
    extra = ctypes.create_string_buffer(len(resp) - OPAQUE_SERVER_SESSION_LEN)
    rw = ctypes.create_string_buffer(crypto_secretbox_KEYBYTES) if rwd else None
    __check(sphinxlib.opaque_session_usr_finish(pwd, len(pwd), resp, sec, key, key_len, sk, extra, rw))
    if rwd:
        return sk.raw, extra.raw, rw.raw
    return sk.raw, extra.raw

# This is a simple utility function that can be used to calculate
# f_k(c), where c is a constant, this is useful if the peers want to
# authenticate each other.
# void sphinx_f(const uint8_t *k, const size_t k_len, const uint8_t val, uint8_t *res);
def opaque_f(k, val):
    if None in (k, val):
        raise ValueError("invalid parameter")

    res = ctypes.create_string_buffer(32)
    v = ctypes.c_uint8(val)
    sphinxlib.sphinx_f(k, len(k), v, res)
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
# int opaque_private_init_usr_start(const uint8_t *pw, const size_t pwlen, uint8_t *r, uint8_t *alpha);
def opaque_private_init_usr_start(pwd):
    if not pwd:
        raise ValueError("invalid parameter")

    r = ctypes.create_string_buffer(32)
    alpha = ctypes.create_string_buffer(32)
    __check(sphinxlib.opaque_private_init_usr_start(pwd, len(pwd), r, alpha))
    return r.raw, alpha.raw

# The server receives alpha from the users invocation of its
# opaque_private_init_usr_start() function, it outputs a value sec
# which needs to be protected until step 4 by the server. This
# function also outputs a value pub which needs to be passed to the
# user.
# int opaque_private_init_srv_respond(const uint8_t *alpha, uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);
def opaque_private_init_srv_respond(alpha):
    if not alpha:
        raise ValueError("invalid parameter")
    if len(alpha) != 32: raise ValueError("invalid alpha param")

    sec = ctypes.create_string_buffer(OPAQUE_REGISTER_SECRET_LEN)
    pub = ctypes.create_string_buffer(OPAQUE_REGISTER_PUBLIC_LEN)
    __check(sphinxlib.opaque_private_init_srv_respond(alpha, sec, pub))
    return sec.raw, pub.raw

# This function is run by the user, taking as input the users password
# pw, the ephemeral secret r that was an output of the user running
# opaque_private_init_usr_start(), and the output pub from the servers
# run of opaque_private_init_srv_respond(). Futhermore the
# extra/extra_len parameter can be used to store additional data in
# the encrypted user record. The result of this is the value rec which
# should be passed for the last step to the server. *Attention* the
# size of rec depends on extra data length. If rwd is not NULL it is
# returned - this enables to run the sphinx protocol in the opaque
# protocol.
# int opaque_private_init_usr_respond(const uint8_t *pw, const size_t pwlen, const uint8_t *r, const uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN], const uint8_t *extra, const uint64_t extra_len, const uint8_t *key, const uint64_t key_len, uint8_t rec[OPAQUE_USER_RECORD_LEN], uint8_t rwd[crypto_secretbox_KEYBYTES]);
def opaque_private_init_usr_respond(pw, r, pub, extra = None, key = None, rwd = False):
    if None in (pw, r, pub):
        raise ValueError("invalid parameter")
    if len(r) != 32: raise ValueError("invalid r param")
    if len(pub) != OPAQUE_REGISTER_PUBLIC_LEN: raise ValueError("invalid pub param")

    rec = ctypes.create_string_buffer(OPAQUE_USER_RECORD_LEN+(len(extra) if extra is not None else 0))
    extralen = ctypes.c_ulonglong(len(extra)) if extra is not None else ctypes.c_ulonglong(0)
    key_len = ctypes.c_ulonglong(len(key)) if key is not None else ctypes.c_ulonglong(0)
    rw = ctypes.create_string_buffer(crypto_secretbox_KEYBYTES) if rwd else None
    __check(sphinxlib.opaque_private_init_usr_respond(pw, len(pw), r, pub, extra, extralen, key, key_len, rec, rw))
    if rwd:
        return rec.raw, rw.raw
    return rec.raw

# The server combines the sec value from its run of its opaque_private_init_srv_respond() function
# with the rec output of the users opaque_private_init_usr_respond() function, creating the final
# record, which should be the same as the output of the 1-step storePwdFile()
# init function of the paper. The server should save this record in
# combination with a user id and/or sid value as suggested in the paper.
# *Attention* the size of rec depends on extra data length.
# void opaque_private_init_srv_finish(const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], const uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN], uint8_t rec[OPAQUE_USER_RECORD_LEN]);
def opaque_private_init_srv_finish(sec, pub, rec):
    if None in (sec, pub, rec):
        raise ValueError("invalid parameter")
    if len(sec) != OPAQUE_REGISTER_SECRET_LEN: raise ValueError("invalid sec param")
    if len(pub) != OPAQUE_REGISTER_PUBLIC_LEN: raise ValueError("invalid pub param")
    if len(rec) < OPAQUE_USER_RECORD_LEN: raise ValueError("invalid rec param")

    sphinxlib.opaque_private_init_srv_finish(sec, pub, rec)
    return rec

