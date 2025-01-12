#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2018-2024, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import sys, os, socket, ssl, struct, time
from SecureString import clearmem
from equihash import solve
import pysodium
try:
  from pwdsphinx import bin2pass
  from pwdsphinx.config import getcfg
  from pwdsphinx.consts import *
except ImportError:
  import bin2pass
  from config import getcfg
  from consts import *

# override consts from consts.py
VERSION = b'\x00'
RULE_SIZE = 79

#### config ####

cfg = getcfg('sphinx')
enabled=False
verbose = cfg['client'].get('verbose', False)
hostname = cfg['client'].get('address')
if hostname is not None:
   enabled = True
   address = socket.gethostbyname(hostname)
   port = int(cfg['client'].get('port',2355))
   try:
     ssl_cert = os.path.expanduser(cfg['client'].get('ssl_cert')) # only for dev, production system should use proper certs!
   except TypeError: # ignore exception in case ssl_cert is not set, thus None is attempted to expand.
     ssl_cert = None

datadir = os.path.expanduser(cfg['client'].get('datadir','~/.config/sphinx'))
#  make RWD optional in (sign|seal)key, if it is b'' then this protects against
#  offline master pwd bruteforce attacks, drawback that for known (host,username) tuples
#  the seeds/blobs can be controlled by an attacker if the masterkey is known
rwd_keys = cfg['client'].get('rwd_keys', False)
validate_password = cfg['client'].get('validate_password',True)
userlist = cfg['client'].get('userlist', True)

if verbose and enabled:
   print("v1 hostname:", hostname, file=sys.stderr)
   print("v1 address:", address, file=sys.stderr)
   print("v1 port:", port, file=sys.stderr)
   print("v1 ssl_cert:", ssl_cert, file=sys.stderr)

#### consts ####

ENC_CTX = b"sphinx encryption key"
SIGN_CTX = b"sphinx signing key"
SALT_CTX = b"sphinx host salt"
PASS_CTX = b"sphinx password context"
CHECK_CTX = b"sphinx check digit context"

#### Helper fns ####

def get_masterkey():
  try:
    with open(os.path.join(datadir,'masterkey'), 'rb') as fd:
        mk = fd.read()
    return mk
  except FileNotFoundError:
    raise ValueError("ERROR: Could not find masterkey!\nIf sphinx was working previously it is now broken.\nIf this is a fresh install all is good, you just need to run `%s init`." % sys.argv[0])

def connect():
  ctx = ssl.create_default_context()
  if(ssl_cert):
      ctx.load_verify_locations(ssl_cert) # only for dev, production system should use proper certs!
      ctx.check_hostname=False            # only for dev, production system should use proper certs!
      ctx.verify_mode=ssl.CERT_NONE       # only for dev, production system should use proper certs!
  else:
      ctx.load_default_certs()
      ctx.verify_mode = ssl.CERT_REQUIRED
      ctx.check_hostname = True

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.settimeout(5)
  s = ctx.wrap_socket(s, server_hostname=hostname)
  s.connect((address, port))
  return s

def get_signkey(id, rwd):
  mk = get_masterkey()
  seed = pysodium.crypto_generichash(SIGN_CTX, mk)
  clearmem(mk)
  # rehash with rwd so the user always contributes his pwd and the sphinx server it's seed
  seed = pysodium.crypto_generichash(seed, id)
  if rwd_keys:
    seed = pysodium.crypto_generichash(seed, rwd)
  pk, sk = pysodium.crypto_sign_seed_keypair(seed)
  clearmem(seed)
  return sk, pk

def get_sealkey():
  mk = get_masterkey()
  sk = pysodium.crypto_generichash(ENC_CTX, mk)
  clearmem(mk)
  return sk

def encrypt_blob(blob):
  # todo implement padding to hide length information
  sk = get_sealkey()
  nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
  ct = pysodium.crypto_aead_xchacha20poly1305_ietf_encrypt(blob,VERSION,nonce,sk)
  clearmem(sk)
  return VERSION+nonce+ct

def decrypt_blob(blob):
  # todo implement padding to hide length information
  sk = get_sealkey()
  version = blob[:1]
  if version > VERSION:
    raise ValueError("Your client is too old to handle this response. Please update your client.")
  blob = blob[1:]
  nonce = blob[:pysodium.crypto_secretbox_NONCEBYTES]
  blob = blob[pysodium.crypto_secretbox_NONCEBYTES:]
  res = pysodium.crypto_aead_xchacha20poly1305_ietf_decrypt(blob,version,nonce,sk)
  clearmem(sk)
  return version, res

def sign_blob(blob, id, rwd):
  sk, pk = get_signkey(id, rwd)
  res = pysodium.crypto_sign_detached(blob,sk)
  clearmem(sk)
  return b''.join((blob,res))

def getid(host, user):
  mk = get_masterkey()
  salt = pysodium.crypto_generichash(SALT_CTX, mk)
  clearmem(mk)
  return pysodium.crypto_generichash(b'|'.join((user.encode(),host.encode())), salt, 32)

def unpack_rule(ct):
  version, packed = decrypt_blob(ct)
  xor_mask = packed[-32:]
  v = int.from_bytes(packed[:-32], "big")

  size = v & ((1<<7) - 1)
  rule = {c for i,c in enumerate(('u','l','d')) if (v >> 7) & (1 << i)}
  symbols = [c for i,c in enumerate(bin2pass.symbols) if (v>>(7+3) & (1<<i))]
  if validate_password:
      check_digit = (v>>(7+3+33))
  else:
      check_digit = 0

  return rule, symbols, size, check_digit, xor_mask

def xor(x,y):
  return bytes(a ^ b for (a, b) in zip(x, y))

def ratelimit(s,req):
  pkt0 = b''.join([CHALLENGE_CREATE, req])
  s.send(pkt0)
  challenge = s.recv(1+1+8+32) # n,k,ts,sig
  if len(challenge)!= 1+1+8+32:
    if verbose: print("challengelen incorrect: %s %s" %(len(challenge), repr(challenge)), file=sys.stderr)
    raise ValueError("ERROR: failed to get ratelimit challenge")
  s.close()
  n = challenge[0]
  k = challenge[1]

  try:
    os.write(3,f"{n} {k}\n".encode('utf8'))
  except OSError: pass

  if k==4:
    if n < 90:
      if verbose: print("got an easy puzzle: %d" % n, file=sys.stderr)
    elif n > 100:
      if verbose: print("got a hard puzzle: %d" % n, file=sys.stderr)
    else:
      if verbose: print("got a moderate puzzle: %d" % n, file=sys.stderr)
  seed = challenge + req

  delta = time.time()
  solution = solve(n, k, seed)
  delta = time.time() - delta
  try:
    os.write(3,f"{delta}".encode('utf8'))
  except OSError: pass

  s = connect()
  pkt1 = b''.join([CHALLENGE_VERIFY, challenge])
  s.send(pkt1)
  s.send(req)
  s.send(solution)
  return s

def auth(s,id,alpha=None,pwd=None,r=None):
  if r is None:
    nonce = s.recv(32)
    if len(nonce)!=32:
       return False
    rwd = b''
  else:
    msg = s.recv(64)
    if len(msg)!=64:
       return False
    beta = msg[:32]
    nonce = msg[32:]
    rwd = finish(pwd, r, alpha, beta, id)

  sk, pk = get_signkey(id, rwd)
  clearmem(rwd)
  sig = pysodium.crypto_sign_detached(nonce,sk)
  clearmem(sk)
  s.send(sig)

  resp = s.recv(6)
  if resp==b'\x00\x04auth': return True
  return False

def challenge(pwd):
  h0 = pysodium.crypto_generichash(pwd, outlen=pysodium.crypto_core_ristretto255_HASHBYTES);
  H0 = pysodium.crypto_core_ristretto255_from_hash(h0)
  clearmem(h0)
  r = pysodium.crypto_core_ristretto255_scalar_random()
  alpha = pysodium.crypto_scalarmult_ristretto255(r, H0)
  clearmem(H0)
  return r, alpha

def finish(pwd, r, alpha, beta, salt):
  if(alpha==beta): raise ValueError("alpha == beta")
  if not pysodium.crypto_core_ristretto255_is_valid_point(alpha): raise ValueError("invalid beta")

  rinv = pysodium.crypto_core_ristretto255_scalar_invert(r)
  H0_k = pysodium.crypto_scalarmult_ristretto255(rinv, beta)
  clearmem(rinv)
  rwd0 = pysodium.crypto_generichash(pwd+H0_k, outlen=pysodium.crypto_core_ristretto255_BYTES);
  clearmem(H0_k)
  rwd = pysodium.crypto_pwhash(pysodium.crypto_core_ristretto255_BYTES,
                               rwd0, salt[:pysodium.crypto_pwhash_SALTBYTES],
                               pysodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
                               pysodium.crypto_pwhash_MEMLIMIT_INTERACTIVE)
  clearmem(rwd0)
  return rwd

#### OPs ####

def get(pwd, user, host):
  if isinstance(pwd, str): pwd = pwd.encode()
  s = connect()
  id = getid(host, user)
  r, alpha = challenge(pwd)
  msg = b''.join([V1GET, id, alpha])
  s = ratelimit(s, msg)

  resp = s.recv(32+RULE_SIZE) # beta + sealed rules
  if resp == b'\x00\x04fail' or len(resp)!=32+RULE_SIZE:
      s.close()
      raise ValueError("ERROR: Either the record does not exist, or the request to server was corrupted during transport.")
  beta = resp[:32]
  rules = resp[32:]
  rwd = finish(pwd, r, alpha, beta, id)

  try:
    classes, symbols, size, checkdigit, xormask = unpack_rule(rules)
  except ValueError:
    s.close()
    raise ValueError("ERROR: failed to unpack password rules from server")
  s.close()

  if validate_password and (checkdigit != (pysodium.crypto_generichash(CHECK_CTX, rwd, 1)[0] & ((1<<5)-1))):
    raise ValueError("ERROR: bad checkdigit")

  rwd = xor(pysodium.crypto_generichash(PASS_CTX, rwd),xormask)
  ret = bin2pass.derive(rwd,classes,size,symbols)
  clearmem(rwd)

  return ret

def delete(pwd, user, host):
  s = connect()
  # run sphinx to recover rwd for authentication
  id = getid(host, user)
  r, alpha = challenge(pwd)
  msg = b''.join([V1DELETE, id, alpha])
  s = ratelimit(s, msg)

  if isinstance(pwd, str): pwd = pwd.encode()
  if not auth(s,id,alpha,pwd,r):
    s.close()
    raise ValueError("ERROR: Failed to authenticate to server while deleting password on server or record doesn't exist")

  if not userlist:
     s.send(b"\0"*96)
  else:
    # delete user from user list for this host
    # a malicous server could correlate all accounts on this services to this users here
    # first query user record for this host
    id = getid(host, '')
    signed_id = sign_blob(id, id, b'')
    s.send(signed_id)
    # wait for user blob
    bsize = s.recv(2)
    bsize = struct.unpack('!H', bsize)[0]
    if bsize == 0:
      # this should not happen, it means something is corrupt
      s.close()
      raise ValueError("ERROR: server has no associated user record for this host", file=sys.stderr)

    blob = s.recv(bsize)
    if blob == b'fail':
      s.close()
      raise ValueError("ERROR: invalid signature on list of users")
    version, blob = decrypt_blob(blob)
    users = set(blob.decode().split('\x00'))
    if user not in users:
      # this should not happen, but maybe it's a sign of corruption?
      s.close()
      raise ValueError(f'warning "{user}" is not in user record', file=sys.stderr)
    users.remove(user)
    blob = ('\x00'.join(sorted(users))).encode()
    # notice we do not add rwd to encryption of user blobs
    blob = encrypt_blob(blob)
    bsize = len(blob)
    if bsize >= 2**16:
      s.close()
      raise ValueError("ERROR: blob is bigger than 64KB.")
    blob = struct.pack("!H", bsize) + blob
    blob = sign_blob(blob, id, b'')

    s.send(blob)

  if b'ok' != s.recv(2):
    s.close()
    raise ValueError("ERROR: server failed to save updated list of user names for host: %s." % host)

  s.close()
  return True

def read_blob(s, id):
  msg = b''.join([READ, id])
  s = ratelimit(s, msg)
  if auth(s,id) is False:
    s.close()
    return
  bsize = s.recv(2)
  bsize = struct.unpack('!H', bsize)[0]
  blob = s.recv(bsize)
  s.close()
  if blob == b'fail':
    return
  return decrypt_blob(blob)

def users(host):
  s = connect()
  res = read_blob(s, getid(host, ''))
  if not res: return set()
  version, res = res
  users = set(res.decode().split('\x00'))
  return users

#print(get(connect(), b'asdf','asdf','test'))
#print(delete(connect(), b'asdf','asdf','test'))
