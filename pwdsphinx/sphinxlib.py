"""Wrapper for libsphinx library

   SPDX-FileCopyrightText: 2018-21, Marsiske Stefan 
   SPDX-License-Identifier: GPL-3.0-or-later  

   This file is part of pwdsphinx.
   
   pwdsphinx is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of
   the License, or (at your option) any later version.

   pwdsphinx is distributed in the hope that it will be
   useful, but WITHOUT ANY WARRANTY; without even the implied
   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the GNU General Public License version 3 for more details.

   You should have received a copy of the GNU General Public License
   along with pitchforked sphinx. If not, see <http://www.gnu.org/licenses/>.
"""

import ctypes
import ctypes.util

sphinxlib = ctypes.cdll.LoadLibrary(ctypes.util.find_library('sphinx') or
                                    ctypes.util.find_library('libsphinx') or
                                    ctypes.util.find_library('libsphinx0'))

if not sphinxlib._name:
    raise ValueError('Unable to find libsphinx')

DECAF_255_SCALAR_BYTES  = 32
DECAF_255_SER_BYTES     = 32
crypto_pwhash_SALTBYTES = 16

def __check(code):
    if code != 0:
        raise ValueError

# void challenge(const uint8_t *pwd, const size_t p_len, const uint8_t *salt, const size_t salt_len, uint8_t *bfac, uint8_t *chal)
def challenge(pwd,salt=''):
    if pwd is None:
        raise ValueError("invalid parameter")
    bfac = ctypes.create_string_buffer(DECAF_255_SCALAR_BYTES)
    chal = ctypes.create_string_buffer(DECAF_255_SER_BYTES)
    sphinxlib.sphinx_challenge(pwd, len(pwd), salt, len(salt), bfac, chal)
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
def finish(pwd, bfac, resp, salt):
    if None in (pwd, bfac, resp, salt):
        raise ValueError("invalid parameter")
    if len(resp) != DECAF_255_SER_BYTES: raise ValueError("truncated point")
    if len(bfac) != DECAF_255_SCALAR_BYTES: raise ValueError("truncated secret")
    if len(salt) < crypto_pwhash_SALTBYTES: raise ValueError("truncated salt")

    rwd = ctypes.create_string_buffer(DECAF_255_SER_BYTES)
    __check(sphinxlib.sphinx_finish(pwd, len(pwd), bfac, resp, salt, rwd))
    return rwd.raw
