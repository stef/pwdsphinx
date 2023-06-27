#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2018-2021, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import sys, os, socket, ssl, struct, platform, getpass, time
from SecureString import clearmem
import pysodium
from qrcodegen import QrCode
from zxcvbn import zxcvbn
from equihash import solve
try:
  from pwdsphinx import bin2pass, sphinxlib
  from pwdsphinx.config import getcfg
  from pwdsphinx.consts import *
except ImportError:
  import bin2pass, sphinxlib
  from config import getcfg
  from consts import *

win=False
if platform.system() == 'Windows':
  win=True

#### config ####

cfg = getcfg('sphinx')

verbose = cfg['client'].getboolean('verbose', fallback=False)
hostname = cfg['client'].get('address','127.0.0.1')
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
rwd_keys = cfg['client'].getboolean('rwd_keys', fallback=False)
validate_password = cfg['client'].getboolean('validate_password',True)

if verbose:
    print("hostname:", hostname, file=sys.stderr)
    print("address:", address, file=sys.stderr)
    print("port:", port, file=sys.stderr)
    print("datadir:", datadir, file=sys.stderr)
    print("ssl_cert:", ssl_cert, file=sys.stderr)
    print("rwd_keys:", rwd_keys, file=sys.stderr)

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
  # todo change this to len(user)|user|len(host)|host
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

def pack_rule(char_classes, syms, size, check_digit, xor_mask=None):
  # pack rules into and encrypt them
  if set(char_classes) - {'u','l','d'}:
    raise ValueError("ERROR: rules can only contain any of 'uld'.")
  if set(syms) - set(bin2pass.symbols) != set():
    raise ValueError("ERROR: symbols can only contain any of '%s'." % bin2pass.symbols)
  if xor_mask is None and (char_classes == '' and len(syms)<2):
    raise ValueError("ERROR: no char classes and not enough symbols specified.")
  if xor_mask is None:
      xor_mask = b'\x00' * 32
  elif len(xor_mask)!=32:
    raise ValueError("ERROR: xor_mask must be 32bytes, is instead: %d." % len(xor_mask))
  if size<0 or size>127:
    raise ValueError("ERROR: invalid max password size: %d." % size)

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
    raise ValueError("Failed to authenticate to server while %s" % "committing" if op == COMMIT else "undoing")
  if s.recv(2)!=b'ok':
    s.close()
    raise ValueError("Server failed to %s" % "Commit" if op == COMMIT else "UNDO")
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
        raise ValueError("ERROR: list of usernames is bigger than 64KB. %d" % bsize)
      blob = struct.pack("!H", bsize) + blob
      # writes need to be signed, and sinces its a new blob, we need to attach the pubkey
      blob = b''.join([pk, blob])
      # again no rwd, to be independent of the master pwd
      blob = sign_blob(blob, id, b'')
    else:
      blob = read_pkt(s, bsize)
      if blob == b'fail':
        s.close()
        raise ValueError("reading list of user names failed")
      version, blob = decrypt_blob(blob)
      items = {x for x in blob.decode().split('\x00') if x}
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
        raise ValueError("ERROR: list of user names is bigger than 64KB. %d" % bsize)
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

def getpwd():
  if sys.stdin.isatty():
    return getpass.getpass("enter your password please: ").encode('utf8')
  else:
    return sys.stdin.buffer.readline().rstrip(b'\n')

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
  except:
    print("ERROR: failed to initialize master key", file=sys.stderr)
    return 1
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
    raise ValueError("ERROR: Creating new password, the record probably already exists or the first message to server was corrupted during transport.")
    # or (less probable) the initial message was longer/shorter than the 65 bytes we sent
    # or (even? less probable) the value alpha received by the server is not a valid point
    # both of these less probable causes point at corruption during transport
  rwd = sphinxlib.finish(pwd, r, beta, id)

  # second phase, derive new auth signing pubkey
  sk, pk = get_signkey(id, rwd)
  clearmem(sk)

  if validate_password:
      checkdigit = pysodium.crypto_generichash(CHECK_CTX, rwd, 1)[0]
  else:
      checkdigit = 0

  if target:
    trwd, char_classes, symbols = bin2pass.pass2bin(target, None)
    xormask = xor(pysodium.crypto_generichash(PASS_CTX, rwd),trwd)
    size = len(target)
    #char_classes = 'uld'
    #symbols = bin2pass.symbols
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
      raise ValueError("ERROR: Either the record does not exist, or the request to server was corrupted during transport.")
  beta = resp[:32]
  rules = resp[32:]
  rwd = sphinxlib.finish(pwd, r, beta, id)

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
    s.close()
    raise ValueError("ERROR: Failed to authenticate using old password to server while changing password on server or record doesn't exist")

  r, alpha = sphinxlib.challenge(newpwd)
  s.send(alpha)
  beta = s.recv(32) # beta
  if beta == b'\x00\x04fail' or len(beta)!=32:
    s.close()
    raise ValueError("ERROR: changing password failed due to corruption during transport.")
  rwd = sphinxlib.finish(newpwd, r, beta, id)

  if validate_password:
      checkdigit = pysodium.crypto_generichash(CHECK_CTX, rwd, 1)[0]
  else:
      checkdigit = 0

  if target:
    trwd, classes, symbols = bin2pass.pass2bin(target, None)
    xormask = xor(pysodium.crypto_generichash(PASS_CTX, rwd),trwd)
    size = len(target)
  else:
    xormask = pysodium.randombytes(32)

  rule = pack_rule(classes, symbols, size, checkdigit, xormask)

  sk, pk = get_signkey(id, rwd)
  clearmem(sk)
  # send over new signed(pubkey)
  s.send(sign_blob(b''.join([pk,rule]), id, rwd))

  if s.recv(2)!=b'ok':
    s.close()
    raise ValueError("ERROR: failed to update password rules on the server during changing of password.")

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
    raise ValueError("ERROR: Failed to authenticate to server while deleting password on server or record doesn't exist")

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
  data = (bytes([1*key+2*rwd_keys + 4*validate_password]) +
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

def usage(params, help=False):
  print("usage: %s init" % params[0])
  print("       echo -n 'password' | %s <create|change> <user> <site> <[u][l][d][s] [<size>] [<symbols>]> | [<target password>]" % params[0])
  print("       echo -n 'password' | %s get <user> <site>" % params[0])
  print("       %s <commit|undo|delete> <user> <site> # if rwd_keys is false in your config" % params[0])
  print("       echo -n 'password' | %s <commit|undo|delete> <user> <site> # if rwd_keys is true in your config" % params[0])
  print("       %s list <site>" % params[0])
  print("       %s qr [svg] [key]" % params[0])
  if help: sys.exit(0)
  sys.exit(100)

def arg_rules(params):
  user = params[2]
  site = params[3]
  size = None
  symbols = None
  classes = None
  target = None
  for param in params[4:]:
    if not classes and set(list(param)) - {'u','l','s','d'} == set():
      if 's' in param:
        symbols = bin2pass.symbols
        classes = ''.join(set(param) - set(['s']))
      else:
        classes = param
        symbols = ''
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
  return user, site, classes or 'uld', symbols if symbols is not None else bin2pass.symbols, size or 0, target

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
  if len(params) < 2: usage(params, True)
  cmd = None
  args = []
  if params[1] in ('help', '-h', '--help'):
    usage(params, True)
  elif params[1] == 'create':
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
  else:
    usage(params)

  error = None
  s = None
  if cmd != users:
    pwd = ''
    if (rwd_keys or cmd in {create,change,get}):
      pwd = getpwd()
      if cmd == change:
        newpwd = getpwd()
        if not newpwd:
          newpwd = pwd
        test_pwd(newpwd)
        args=(newpwd,) + args
      if cmd == create:
        test_pwd(pwd)
    try:
      s = connect()
      ret = cmd(s, pwd, *args)
    except Exception as exc:
      error = exc
      ret = False
      #raise # only for dbg
    clearmem(pwd)
  else:
    try:
      s = connect()
      ret = cmd(s,  *args)
    except Exception as exc:
      error = exc
      ret = False
      #raise # only for dbg
  if s and s.fileno() != -1: s.close()

  if not ret:
    if not error:
        print("fail", file=sys.stderr)
        sys.exit(3) # error not handled by exception
    print(error, file=sys.stderr)
    if str(error) == "ERROR: bad checkdigit":
      sys.exit(2) # bad check digit
    sys.exit(1) # generic errors

  if cmd not in {delete, undo, commit}:
    print(ret)
    sys.stdout.flush()
    clearmem(ret)
  elif ret != True:
    print("reached code that should not be reachable: ", ret)

if __name__ == '__main__':
  try:
    main(sys.argv)
  except Exception:
    print("fail", file=sys.stderr)
    #raise # only for dbg
