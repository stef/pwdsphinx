#!/usr/bin/env python

# SPDX-FileCopyrightText: 2018, Marsiske Stefan 
# SPDX-License-Identifier: GPL-3.0-or-later

import sphinxlib as o

pwd = "simple guessable dictionary password"
print "trying server inspects password registration flow"
rec = o.opaque_store(pwd)
pub, sec = o.opaque_usrSession(pwd)
resp, sk_s = o.opaque_srvSession(pub, rec)
sk_u = o.opaque_usrSessionEnd(pwd, resp, sec)
print "sk_s", repr(sk_s)
print "sk_u", repr(sk_u)
assert(sk_s == sk_u)
print "f(sk_s,0)", repr(o.opaque_f(sk_s, '0'))
print "f(sk_u,0)", repr(o.opaque_f(sk_u, '0'))
assert(o.opaque_f(sk_s, '0')==o.opaque_f(sk_u, '0'))

print "trying alternative/private registration flow"
# alternative/private registration flow:
r, alpha = o.opaque_newUser(pwd)
sec_s, pub_s = o.opaque_initUser(alpha)
rec = o.opaque_registerUser(pwd, r, pub_s)
rec = o.opaque_saveUser(sec_s, pub_s, rec)

pub, sec = o.opaque_usrSession(pwd)
resp, sk_s = o.opaque_srvSession(pub, rec)
sk_u = o.opaque_usrSessionEnd(pwd, resp, sec)
print "sk_s", repr(sk_s)
print "sk_u", repr(sk_u)
assert(sk_s == sk_u)
print "f(sk_s,1)", repr(o.opaque_f(sk_s, '1'))
print "f(sk_u,1)", repr(o.opaque_f(sk_u, '1'))
assert(o.opaque_f(sk_s, '1')==o.opaque_f(sk_u, '1'))
