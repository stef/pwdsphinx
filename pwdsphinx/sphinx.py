#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2018-2021, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import sys, os, socket, ssl, struct, platform
from SecureString import clearmem
import pysodium
from qrcodegen import QrCode
from zxcvbn import zxcvbn
from equihash import solve
try:
  from pwdsphinx import bin2pass, sphinxlib
  from pwdsphinx.config import getcfg
except ImportError:
  import bin2pass, sphinxlib
  from config import getcfg

win=False
if platform.system() == 'Windows':
  win=True

#### config ####

cfg = getcfg('sphinx')

verbose = cfg['client'].getboolean('verbose', fallback=False)
hostname = cfg['client']['address']
address = socket.gethostbyname(hostname)
port = int(cfg['client'].get('port',2355))
datadir = os.path.expanduser(cfg['client'].get('datadir','~/.config/sphinx'))
try:
  ssl_cert = os.path.expanduser(cfg['client'].get('ssl_cert')) # only for dev, production system should use proper certs!
except TypeError: # ignore exception in case ssl_cert is not set, thus None is attempted to expand.
  ssl_cert = None
#  make RWD optional in (sign|seal)key, if it is b'' then this protects against
#  offline master pwd bruteforce attacks, drawback that for known (host,username) tuples
#  the seeds/blobs can be controlled by an attacker if the masterkey is known
rwd_keys = not not cfg['client'].get('rwd_keys',False)

if verbose:
    print("hostname:", hostname, file=sys.stderr)
    print("address:", address, file=sys.stderr)
    print("port:", port, file=sys.stderr)
    print("datadir:", datadir, file=sys.stderr)
    print("ssl_cert:", ssl_cert, file=sys.stderr)
    print("rwd_keys:", rwd_keys, file=sys.stderr)

#### consts ####

CREATE   =b'\x00' # sphinx
READ     =b'\x33' # blob
UNDO     =b'\x55' # change sphinx
GET      =b'\x66' # sphinx
COMMIT   =b'\x99' # change sphinx
CHANGE   =b'\xaa' # sphinx
DELETE   =b'\xff' # sphinx+blobs

CHALLENGE_CREATE = b'\x5a'
CHALLENGE_VERIFY = b'\xa5'

ENC_CTX = b"sphinx encryption key"
SIGN_CTX = b"sphinx signing key"
SALT_CTX = b"sphinx host salt"
PASS_CTX = b"sphinx password context"
CHECK_CTX = b"sphinx check digit context"

VERSION = b'\x00'

RULE_SIZE = 79

#### Helper fns ####

def get_masterkey():
  try:
    with open(os.path.join(datadir,'masterkey'), 'rb') as fd:
        mk = fd.read()
    return mk
  except FileNotFoundError:
    print("Error: Could not find masterkey!\nIf sphinx was working previously it is now broken.\nIf this is a fresh install all is good, you just need to run `%s init`." % sys.argv[0])
    sys.exit(1)

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
  # todo implement padding
  sk = get_sealkey()
  nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
  ct = pysodium.crypto_aead_xchacha20poly1305_ietf_encrypt(blob,VERSION,nonce,sk)
  clearmem(sk)
  return VERSION+nonce+ct

def decrypt_blob(blob):
  # todo implement padding
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
  check_digit = (v>>(7+3+33))

  return rule, symbols, size, check_digit, xor_mask

def pack_rule(char_classes, syms, size, check_digit, xor_mask=None):
  # pack rules into and encrypt them
  if set(char_classes) - {'u','l','d'}:
    raise ValueError("error: rules can only contain any of 'uld'.")
  if set(syms) - set(bin2pass.symbols) != set():
    raise ValueError("error: symbols can only contain any of '%s'." % bin2pass.symbols)
  if xor_mask is None and (char_classes == '' and len(syms)<2):
    raise ValueError("error: no char classes and not enough symbols specified.")
  if xor_mask is None:
      xor_mask = b'\x00' * 32
  elif len(xor_mask)!=32:
    raise ValueError("error: xor_mask must be 32bytes, is instead: %d." % len(xor_mask))
  if size<0 or size>127:
    raise ValueError("error: invalid max password size: %d." % size)

  packed = size
  packed = packed + (sum(1<<i for i, c in enumerate(('u','l','d')) if c in char_classes) << 7)
  packed = packed + (sum(1<<i for i, c in enumerate(bin2pass.symbols) if c in syms) << (7 + 3))
  packed = packed + ((check_digit & ((1<<5) - 1)) << (7 + 3 + 33) )
  pt = packed.to_bytes(6,"big") + xor_mask
  return encrypt_blob(pt)

def xor(x,y):
  return bytes(a ^ b for (a, b) in zip(x, y))

def commit_undo(s, op, pwd, user, host):
  id = getid(host, user)
  r, alpha = sphinxlib.challenge(pwd)
  msg = b''.join([op, id, alpha])
  s = ratelimit(s, msg)
  if not auth(s,id,pwd,r):
    s.close()
    raise ValueError("auth failed")
  if s.recv(2)!=b'ok':
    print("ohoh, something is corrupt, and this is a bad, very bad error message in so many ways", file=sys.stderr)
    s.close()
    raise ValueError("Operation failed")
  s.close()
  return True

def read_pkt(s,size):
    res = []
    read = 0
    while read<size or len(res[-1])==0:
      res.append(s.recv(size-read))
      read+=len(res[-1])

    return b''.join(res)

def update_rec(s, host, item): # this is only for user blobs. a UI feature offering a list of potential usernames.
    id = getid(host, '')
    signed_id = sign_blob(id, id, b'')
    s.send(signed_id)
    # wait for user blob
    bsize = s.recv(2)
    bsize = struct.unpack('!H', bsize)[0]
    if bsize == 0:
      # it is a new blob, we need to attach an auth signing pubkey
      sk, pk = get_signkey(id, b'')
      clearmem(sk)
      # we encrypt with an empty rwd, so that the user list is independent of the master pwd
      blob = encrypt_blob(item.encode())
      bsize = len(blob)
      if bsize >= 2**16:
        s.close()
        raise ValueError("error: blob is bigger than 64KB. %d" % bsize)
      blob = struct.pack("!H", bsize) + blob
      # writes need to be signed, and sinces its a new blob, we need to attach the pubkey
      blob = b''.join([pk, blob])
      # again no rwd, to be independent of the master pwd
      blob = sign_blob(blob, id, b'')
    else:
      blob = read_pkt(s, bsize)
      if blob == b'fail':
        s.close()
        raise ValueError("reading user blob failed")
      version, blob = decrypt_blob(blob)
      items = set(blob.decode().split('\x00'))
      # this should not happen, but maybe it's a sign of corruption?
      if item in items:
        print(f'warning: "{item}" is already in the user record', file=sys.stderr)
      items.add(item)
      blob = ('\x00'.join(sorted(items))).encode()
      # notice we do not add rwd to encryption of user blobs
      blob = encrypt_blob(blob)
      bsize = len(blob)
      if bsize >= 2**16:
        s.close()
        raise ValueError("error: blob is bigger than 64KB. %d" % bsize)
      blob = struct.pack("!H", bsize) + blob
      blob = sign_blob(blob, id, b'')
    s.send(blob)

def auth(s,id,pwd=None,r=None):
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
    rwd = sphinxlib.finish(pwd, r, beta, id)

  sk, pk = get_signkey(id, rwd)
  sig = pysodium.crypto_sign_detached(nonce,sk)
  clearmem(sk)
  s.send(sig)
  return rwd

def ratelimit(s,req):
  pkt0 = b''.join([CHALLENGE_CREATE, req])
  s.send(pkt0)
  challenge = s.recv(1+1+8+32) # n,k,ts,sig
  if len(challenge)!= 1+1+8+32:
    print("challengelen incorrect: %s %s" %(len(challenge), repr(challenge)), file=sys.stderr)
    raise ValueError("failed to get ratelimit challenge")
  s.close()
  n = challenge[0]
  k = challenge[1]
  if k==4:
    if n < 90:
      if verbose: print("got an easy puzzle: %d" % n, file=sys.stderr)
    elif n > 100:
      if verbose: print("got a hard puzzle: %d" % n, file=sys.stderr)
    else:
      if verbose: print("got a moderate puzzle: %d" % n, file=sys.stderr)
  seed = challenge + req
  solution = solve(n, k, seed)
  s = connect()
  pkt1 = b''.join([CHALLENGE_VERIFY, challenge])
  s.send(pkt1)
  s.send(req)
  s.send(solution)
  return s

#### OPs ####

def init_key():
  kfile = os.path.join(datadir,'masterkey')
  if os.path.exists(kfile):
    print("Already initialized.", file=sys.stderr)
    return 1
  if not os.path.exists(datadir):
    os.makedirs(datadir, 0o700, exist_ok=True)
  mk = pysodium.randombytes(32)
  try:
    with open(kfile,'wb') as fd:
      if not win: os.fchmod(fd.fileno(),0o600)
      fd.write(mk)
  finally:
    clearmem(mk)
  return 0

def create(s, pwd, user, host, char_classes='uld', symbols=bin2pass.symbols, size=0, target=None):
  # 1st step OPRF on the new seed
  id = getid(host, user)
  r, alpha = sphinxlib.challenge(pwd)
  msg = b''.join([CREATE, id, alpha])
  s.send(msg)

  # wait for response from sphinx server
  beta = s.recv(32)
  if beta == b'\x00\x04fail':
    s.close()
    raise ValueError("error: sphinx protocol failure.")
  rwd = sphinxlib.finish(pwd, r, beta, id)

  # second phase, derive new auth signing pubkey
  sk, pk = get_signkey(id, rwd)
  clearmem(sk)

  checkdigit = pysodium.crypto_generichash(CHECK_CTX, rwd, 1)[0]

  if target:
    xormask = xor(pysodium.crypto_generichash(PASS_CTX, rwd),bin2pass.pass2bin(target))
    size = len(target)
    char_classes = 'uld'
    symbols = bin2pass.symbols
  else:
    xormask = pysodium.randombytes(32)

  rule = pack_rule(char_classes, symbols, size, checkdigit, xormask)
  # send over new signed(pubkey, rule)
  msg = b''.join([pk, rule])
  msg = sign_blob(msg, id, rwd)
  s.send(msg)

  # add user to user list for this host
  # a malicous server could correlate all accounts on this services to this users here
  update_rec(s, host, user)
  s.close()

  rwd = xor(pysodium.crypto_generichash(PASS_CTX, rwd),xormask)

  ret = bin2pass.derive(rwd,char_classes,size,symbols)
  clearmem(rwd)
  return ret

def get(s, pwd, user, host):
  id = getid(host, user)
  r, alpha = sphinxlib.challenge(pwd)
  msg = b''.join([GET, id, alpha])
  s = ratelimit(s, msg)

  resp = s.recv(32+RULE_SIZE) # beta + sealed rules
  if resp == b'\x00\x04fail' or len(resp)!=32+RULE_SIZE:
      s.close()
      raise ValueError("error: sphinx protocol failure.")
  beta = resp[:32]
  rules = resp[32:]
  rwd = sphinxlib.finish(pwd, r, beta, id)

  try:
    classes, symbols, size, checkdigit, xormask = unpack_rule(rules)
  except ValueError:
    s.close()
    return
  s.close()

  if (checkdigit != (pysodium.crypto_generichash(CHECK_CTX, rwd, 1)[0] & ((1<<5)-1))):
    raise ValueError("bad checkdigit")

  rwd = xor(pysodium.crypto_generichash(PASS_CTX, rwd),xormask)
  ret = bin2pass.derive(rwd,classes,size,symbols)
  clearmem(rwd)

  return ret

def read_blob(s, id, rwd = b''):
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

def users(s, host):
  res = read_blob(s, getid(host, ''))
  if not res: return "no users found"
  version, res = res
  users = set(res.decode().split('\x00'))
  return '\n'.join(sorted(users))

def change(s, oldpwd, newpwd, user, host, classes='uld', symbols=bin2pass.symbols, size=0, target=None):
  id = getid(host, user)
  r, alpha = sphinxlib.challenge(oldpwd)
  msg = b''.join([CHANGE, id, alpha])
  s = ratelimit(s, msg)
  # auth: do sphinx with current seed, use it to sign the nonce
  if not auth(s,id,oldpwd,r):
    print('failed authentication', file=sys.stderr)
    s.close()
    return

  r, alpha = sphinxlib.challenge(newpwd)
  s.send(alpha)
  beta = s.recv(32) # beta
  if beta == b'\x00\x04fail' or len(beta)!=32:
    s.close()
    raise ValueError("error: sphinx protocol failure.")
  rwd = sphinxlib.finish(newpwd, r, beta, id)

  checkdigit = pysodium.crypto_generichash(CHECK_CTX, rwd, 1)[0]

  if target:
    xormask = xor(pysodium.crypto_generichash(PASS_CTX, rwd),bin2pass.pass2bin(target))
    size = len(target)
    classes = 'uld'
    symbols = bin2pass.symbols
  else:
    xormask = pysodium.randombytes(32)

  rule = pack_rule(classes, symbols, size, checkdigit, xormask)

  sk, pk = get_signkey(id, rwd)
  clearmem(sk)
  # send over new signed(pubkey)
  s.send(sign_blob(b''.join([pk,rule]), id, rwd))

  if s.recv(2)!=b'ok':
    print("ohoh, something is corrupt, and this is a bad, very bad error message in so many ways", file=sys.stderr)
    s.close()
    return

  s.close()
  rwd = xor(pysodium.crypto_generichash(PASS_CTX, rwd),xormask)
  ret = bin2pass.derive(rwd,classes,size,symbols)
  clearmem(rwd)

  return ret

def commit(s, pwd, user, host):
  return commit_undo(s, COMMIT, pwd, user, host)

def undo(s, pwd, user, host):
  return commit_undo(s, UNDO, pwd, user, host)

def delete(s, pwd, user, host):
  # run sphinx to recover rwd for authentication
  id = getid(host, user)
  r, alpha = sphinxlib.challenge(pwd)
  msg = b''.join([DELETE, id, alpha])
  s = ratelimit(s, msg)
  rwd = auth(s,id,pwd,r)
  if not rwd:
    s.close()
    return

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
    print("error: server has no associated user record for this host", file=sys.stderr)
    s.close()
    return

  blob = s.recv(bsize)
  # todo handle this
  if blob == b'fail':
    s.close()
    return
  version, blob = decrypt_blob(blob)
  users = set(blob.decode().split('\x00'))
  if user not in users:
    # this should not happen, but maybe it's a sign of corruption?
    print(f'warning "{user}" is not in user record', file=sys.stderr)
  users.remove(user)
  blob = ('\x00'.join(sorted(users))).encode()
  # notice we do not add rwd to encryption of user blobs
  blob = encrypt_blob(blob)
  bsize = len(blob)
  if bsize >= 2**16:
    s.close()
    raise ValueError("error: blob is bigger than 64KB.")
  blob = struct.pack("!H", bsize) + blob
  blob = sign_blob(blob, id, b'')

  s.send(blob)

  if b'ok' != s.recv(2):
    s.close()
    return

  s.close()
  clearmem(rwd)
  return True

def print_qr(qrcode: QrCode) -> None:
  chars = {
    (True, True):    ' ',      # empty
    (False, True):   '\u2580', # upper
    (True, False):   '\u2584', # lower
    (False, False):  '\u2588', # full
  }
  border = 1
  for y in range(-border, qrcode.get_size() + border, 2):
    for x in range(-border, qrcode.get_size() + border):
      print(chars[(qrcode.get_module(x,y),qrcode.get_module(x,y+1))], end="")
    print()
  print()


def qrcode(output, key):
  mk=get_masterkey() if key else b''
  data = (bytes([1*key+2*rwd_keys]) +
          mk +
          struct.pack("!H", port) +
          hostname.encode("utf8"))

  qr = QrCode.encode_binary(data, QrCode.Ecc.LOW)
  if key:
    clearmem(mk)
    clearmem(data)
  if output=='txt':
    print_qr(qr)
  else:
    print(qr.to_svg_str(2))

def usage(params):
  print("usage: %s init" % params[0])
  print("usage: %s <create|change> <user> <site> <[u][l][d][s] [<size>] [<symbols>]> | [<target password>]" % params[0])
  print("usage: %s <get|commit|undo|delete> <user> <site>" % params[0])
  print("usage: %s list <site>" % params[0])
  print("usage: %s qr [svg] [key]" % params[0])
  sys.exit(1)

def arg_rules(params):
  user = params[2]
  site = params[3]
  size = None
  symbols = ''
  classes = ''
  target = None
  for param in params[4:]:
    if not classes and set(list(param)) - {'u','l','s','d'} == set():
      if 's' in param:
        symbols = bin2pass.symbols
        classes = ''.join(set(param) - set(['s']))
      else:
        classes = param
      continue
    if not size:
      try:
        tmp = int(param)
        if tmp<79:
          size = tmp
          continue
      except: pass
    if set(param) - set(bin2pass.symbols) == set():
      symbols = param
      continue
    if verbose: print(f'using "{param}" as target password', file=sys.stderr)
    target = param
  if target is not None and (symbols or classes or size):
    print(f"invalid args for {param[1]}: \"{params[4:]}\"", file=sys.stderr)
    usage(param)
  return user, site, classes or '', symbols, size or 0, target

def test_pwd(pwd):
  q = zxcvbn(pwd.decode('utf8'))
  print("your %s%s (%s/4) master password can be online recovered in %s, and offline in %s, trying ~%s guesses" %
        ("★" * q['score'],
         "☆" * (4-q['score']),
         q['score'],
         q['crack_times_display']['online_throttling_100_per_hour'],
         q['crack_times_display']['offline_slow_hashing_1e4_per_second'],
         q['guesses']), file=sys.stderr)

#### main ####

def main(params=sys.argv):
  if len(params) < 2: usage(params)
  cmd = None
  args = []
  if params[1] == 'create':
    try:
      user,site,classes, syms, size, target = arg_rules(params)
    except: usage(params)
    cmd = create
    args = (user, site, classes, syms, size, target)
  elif params[1] == 'init':
    if len(params) != 2: usage(params)
    sys.exit(init_key())
  elif params[1] == 'get':
    if len(params) != 4: usage(params)
    cmd = get
    args = (params[2], params[3])
  elif params[1] == 'change':
    try:
      user,site,classes,syms,size, target = arg_rules(params)
    except: usage(params)
    cmd = change
    args = (user, site, classes, syms, size, target)
  elif params[1] == 'commit':
    if len(params) != 4: usage(params)
    cmd = commit
    args = (params[2], params[3])
  elif params[1] == 'delete':
    if len(params) != 4: usage(params)
    cmd = delete
    args = (params[2], params[3])
  elif params[1] == 'list':
    if len(params) != 3: usage(params)
    cmd = users
    args = (params[2],)
  elif params[1] == 'undo':
    if len(params) != 4: usage(params)
    cmd = undo
    args = (params[2],params[3])
  elif params[1] == 'qr':
    cmd = qrcode
    output = 'txt'
    key = False
    if "svg" in params:
      output="svg"
      del params[params.index("svg")]
    if "key" in params:
      key=True
      del params[params.index("key")]
    if params[2:]: usage(params)
    qrcode(output, key)
    return

  if cmd is not None:
    if cmd != users:
      pwd = sys.stdin.buffer.readline().rstrip(b'\n')
      if cmd == change:
        newpwd = sys.stdin.buffer.readline().rstrip(b'\n')
        if not newpwd:
          newpwd = pwd
        test_pwd(newpwd)
        args=(newpwd,) + args
      if cmd == create:
        test_pwd(pwd)
      try:
        s = connect()
        ret = cmd(s, pwd, *args)
      except:
        ret = False
        raise # todo remove only for dbg
      clearmem(pwd)
    else:
      try:
        s = connect()
        ret = cmd(s,  *args)
      except:
        ret = False
        raise # todo remove only for dbg
    s.close() # todo is still needed?
    if not ret:
      print("fail", file=sys.stderr)
      sys.exit(1)
    if cmd not in {delete, undo, commit}:
      print(ret)
      sys.stdout.flush()
      clearmem(ret)
  else:
    usage()

if __name__ == '__main__':
  try:
    main(sys.argv)
  except Exception:
    print("fail", file=sys.stderr)
    raise # todo remove only for dbg
