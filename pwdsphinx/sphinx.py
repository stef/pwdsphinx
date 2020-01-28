#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2018, Marsiske Stefan 
# SPDX-License-Identifier: GPL-3.0-or-later 

import sys, os, socket, ssl, io, struct, binascii, platform
from SecureString import clearmem
import pysodium
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

verbose = cfg['client'].getboolean('verbose')
address = cfg['client']['address']
port = int(cfg['client']['port'])
datadir = os.path.expanduser(cfg['client']['datadir'])
ssl_cert = cfg['client']['ssl_cert'] # TODO only for dev, production system should use proper certs!

#### consts ####

CREATE   =b'\x00' # sphinx
READ     =b'\x0f' # blob
BACKUP   =b'\x33' # sphinx+blobs
UNDO     =b'\x55' # change sphinx
GET      =b'\x66' # sphinx
COMMIT   =b'\x99' # change sphinx
CHANGE   =b'\xaa' # sphinx
WRITE    =b'\xcc' # blob
DELETE   =b'\xff' # sphinx+blobs

ENC_CTX = "sphinx encryption key"
SIGN_CTX = "sphinx signing key"
SALT_CTX = "sphinx host salt"
ROOT_CTX = "sphinx root idx"
PASS_CTX = "sphinx password context"

#### Helper fns ####

def get_masterkey():
  try:
    with open(os.path.join(datadir,'masterkey'), 'rb') as fd:
        mk = fd.read()
    return mk
  except FileNotFoundError:
    print("Error: Could not find masterkey!\nIf sphinx was working previously it is now broken.\nIf this is a fresh install all is good, you just need to run `%s init`." % sys.argv[0])
    sys.exit(1)

def split_by_n(obj, n):
  # src https://stackoverflow.com/questions/9475241/split-string-every-nth-character
  return [obj[i:i+n] for i in range(0, len(obj), n)]

def connect():
  ctx = ssl.create_default_context()
  ctx.load_verify_locations(ssl_cert) # TODO only for dev, production system should use proper certs!
  ctx.check_hostname=False            # TODO only for dev, production system should use proper certs!
  ctx.verify_mode=ssl.CERT_NONE       # TODO only for dev, production system should use proper certs!

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s = ctx.wrap_socket(s)
  s.connect((address, port))
  return s

def get_signkey(id, rwd):
  mk = get_masterkey()
  seed = pysodium.crypto_generichash(SIGN_CTX, mk)
  clearmem(mk)
  # rehash with rwd so the user always contributes his pwd and the sphinx server it's seed
  seed = pysodium.crypto_generichash(seed, id)
  seed = pysodium.crypto_generichash(seed, rwd)
  pk, sk = pysodium.crypto_sign_seed_keypair(seed)
  clearmem(seed)
  return sk, pk

def get_sealkey(rwd):
  mk = get_masterkey()
  sk = pysodium.crypto_generichash(ENC_CTX, mk)
  clearmem(mk)
  # rehash with rwd so the user always contributes his pwd and the sphinx server it's seed
  sk = pysodium.crypto_generichash(sk, rwd)
  pk = pysodium.crypto_scalarmult_curve25519_base(sk)
  return sk, pk

def encrypt_blob(blob, rwd):
  # todo implement padding
  sk, pk = get_sealkey(rwd)
  clearmem(sk)
  return pysodium.crypto_box_seal(blob,pk)

def decrypt_blob(blob, rwd):
  # todo implement padding
  sk, pk = get_sealkey(rwd)
  res = pysodium.crypto_box_seal_open(blob,pk,sk)
  clearmem(sk)
  return res

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

def getrootid():
  mk = get_masterkey()
  root = pysodium.crypto_generichash(ROOT_CTX, mk)
  clearmem(mk)
  return root

def unpack_rule(rules, rwd):
  rules = decrypt_blob(rules, rwd)
  rule = struct.unpack(">H",rules)[0]
  size = (rule & 0x7f)
  rule = {c for i,c in enumerate(('u','l','s','d')) if (rule >> 7) & (1 << i)}
  return rule, size

def pack_rule(char_classes, size):
  # pack rules into 2 bytes, and encrypt them
  if set(char_classes) - {'u','l','s','d'}:
    raise ValueError("error: rules can only contain any of 'ulsd'.")

  rules = sum(1<<i for i, c in enumerate(('u','l','s','d')) if c in char_classes)
  # pack rule
  return struct.pack('>H', (rules << 7) | (size & 0x7f))

def doSphinx(s, op, pwd, user, host):
  id = getid(host, user)
  r, alpha = sphinxlib.challenge(pwd)
  msg = b''.join([op, id, alpha])
  s.send(msg)
  crwd = None
  if op != GET: # == CHANGE, UNDO, COMMIT
    # do sphinx with current seed, use it to sign the nonce
    msg = s.recv(64)
    beta = msg[:32]
    nonce = msg[32:]
    crwd = sphinxlib.finish(pwd, r, beta, id)
    sk, pk = get_signkey(id, crwd)
    sig = pysodium.crypto_sign_detached(nonce,sk)
    clearmem(sk)
    s.send(sig)

  resp = s.recv(32+50) # beta + sealed rules
  if resp == b'fail' or len(resp)!=32+50:
    raise ValueError("error: sphinx protocol failure.")
  beta = resp[:32]
  rules = resp[32:]
  rwd = sphinxlib.finish(pwd, r, beta, id)

  # in case of change/undo/commit we need to use the crwd to decrypt the rules
  classes, size = unpack_rule(rules, crwd or rwd)
  if crwd:
    clearmem(crwd)
    # in case of undo/commit we also need to rewrite the rules and pub auth signing key blob
    if op in {UNDO,COMMIT}:
      sk, pk = get_signkey(id, rwd)
      clearmem(sk)
      rule = encrypt_blob(pack_rule(classes, size), rwd)

      # send over new signed(pubkey, rule)
      msg = b''.join([pk, rule])
      msg = sign_blob(msg, id, rwd)
      s.send(msg)
      if s.recv(2)!=b'ok':
        print("ohoh, something is corrupt, and this is a bad, very bad error message in so many ways")
        return False

  rpwd = bin2pass.derive(pysodium.crypto_generichash(PASS_CTX, rwd),classes,size).decode()
  clearmem(rwd)
  print(rpwd)
  clearmem(rpwd)

  return True

#### OPs ####

def init_key():
  kfile = os.path.join(datadir,'masterkey')
  if os.path.exists(kfile):
    print("Already initialized.")
    return 1
  if not os.path.exists(datadir):
    os.mkdir(datadir,0o700)
  mk = pysodium.randombytes(32)
  try:
    with open(kfile,'wb') as fd:
      if not win: os.fchmod(fd.fileno(),0o600)
      fd.write(mk)
  finally:
    clearmem(mk)
  return 0

def create(s, pwd, user, host, char_classes, size=0):
  # 1st step OPRF on the new seed
  id = getid(host, user)
  r, alpha = sphinxlib.challenge(pwd)
  msg = b''.join([CREATE, id, alpha])
  s.send(msg)

  # wait for response from sphinx server
  beta = s.recv(32)
  if beta == b'fail':
    raise ValueError("error: sphinx protocol failure.")
  rwd = sphinxlib.finish(pwd, r, beta, id)

  # second phase, derive new auth signing pubkey
  sk, pk = get_signkey(id, rwd)
  clearmem(sk)

  try: size=int(size)
  except:
    raise ValueError("error: size has to be integer.")
  rule = encrypt_blob(pack_rule(char_classes, size), rwd)

  # send over new signed(pubkey, rule)
  msg = b''.join([pk, rule])
  msg = sign_blob(msg, id, rwd)
  s.send(msg)

  # add user to user list for this host
  # a malicous server could correlate all accounts on this services to this users here
  # first query user record for this host
  id = getid(host, '')
  s.send(id)
  # wait for user blob
  blob = s.recv(8192)  # todo/fixme this is an arbitrary limit
  if blob == b'none':
    # it is a new blob, we need to attach an auth signing pubkey
    sk, pk = get_signkey(id, b'')
    clearmem(sk)
    blob = encrypt_blob(user.encode(), b'')
    # writes need to be signed, and sinces its a new blob, we need to attach the pubkey
    blob = b''.join([pk, blob])
    blob = sign_blob(blob, id, b'')
  else:
    blob = decrypt_blob(blob, b'')
    users = set(blob.decode().split('\x00'))
    # todo/fix? we do not recognize if the user is already included in this list
    # this should not happen, but maybe it's a sign of corruption?
    users.add(user)
    blob = ('\x00'.join(sorted(users))).encode()
    # notice we do not add rwd to encryption of user blobs
    blob = encrypt_blob(blob, b'')
    blob = sign_blob(blob, id, b'')
  s.send(blob)

  # add host to list of hosts for this
  id = getrootid()
  s.send(id)

  blob = s.recv(8192)  # todo/fixme this is an arbitrary limit
  if blob == b'none':
    # it is a new blob, we need to attach an auth signing pubkey
    sk, pk = get_signkey(id, b'')
    clearmem(sk)
    blob = encrypt_blob(host.encode(), b'')
    msg = b''.join([pk, blob])
    # writes need to be signed, and sinces its a new blob, we need to attach the pubkey
    msg = sign_blob(msg, id, b'')
  else:
    blob = decrypt_blob(blob, b'')
    hosts = set(blob.decode().split('\x00'))
    # todo/fix? we do not recognize if the host is already included in this list
    # this should not happen, but maybe it's a sign of corruption?
    hosts.add(host)
    blob = ('\x00'.join(sorted(hosts))).encode()
    # notice we do not add rwd to encryption of user blobs
    blob = encrypt_blob(blob, b'')
    msg = sign_blob(blob, id, b'')
  s.send(msg)

  print(bin2pass.derive(pysodium.crypto_generichash(PASS_CTX, rwd),char_classes,size).decode())
  clearmem(rwd)
  return True

def get(s, pwd, user, host):
  return doSphinx(s, GET, pwd, user, host)

def read_blob(s, host=None, id=None, rwd = None):
  if id is None:
    if host is not None:
        id = getid(host, '')
    else:
      fail(s)
      raise ValueError("must have either host or id provided in params")
  if rwd is None:
    rwd = b''
  msg = b''.join([READ, id])
  msg = sign_blob(msg, id, rwd)
  s.send(msg)
  blob = s.recv(4096)
  if blob == b'fail':
    return b''
  return decrypt_blob(blob, rwd)

def users(s, host):
  users = set(read_blob(s, host).decode().split('\x00'))
  print('\n'.join(sorted(users)))
  return True

def change(s, pwd, user, host):
  return doSphinx(s, CHANGE, pwd, user, host)

def commit(s, pwd, user, host):
  return doSphinx(s, COMMIT, pwd, user, host)

def undo(s, pwd, user, host):
  return doSphinx(s, UNDO, pwd, user, host)

### here be dragons ####

def write_blob(s, blob, host=None, id=None):
  if id is None:
    if host is not None:
        id = getid(host, '')
    else:
      fail(s)
      raise ValueError("must have either host or id provided in params")
  blob = encrypt_blob(blob)
  sk, pk = get_signkey()
  clearmem(sk)
  msg = b''.join([WRITE, pk, id, blob])
  msg = sign_blob(msg)
  s.send(msg)
  blob = s.recv(4096)
  return blob == b'ok'

def delete(s, user, host):
  id = getid(host, user)
  msg = b''.join([DELETE, id])
  msg = sign_blob(msg)
  s.send(msg)
  blob = s.recv(4096)
  # todo implement remove user and remove host
  return blob == b'ok'

def backup(s): # todo implement
  id = getrootid()
  ret = read_blob(s, id = id)
  if ret==b'':
    return
  hosts = set(ret.decode().split('\x00'))
  for host in hosts:
    print("host:", host)
    s.close()
    s = connect()
    ret = read_blob(s, id = getid(host,''))
    if ret == b'': continue
    users = set(ret.decode().split('\x00'))
    for u in users:
      print("\t", u)
  return True

#### main ####

def main():
  def usage():
    print("usage: %s init" % sys.argv[0])
    print("usage: %s create <user> <site> [u][l][d][s] [<size>]" % sys.argv[0])
    print("usage: %s <get|change|commit|undo|delete> <user> <site>" % sys.argv[0])
    print("usage: %s list <site>" % sys.argv[0])
    print("usage: %s backup" % sys.argv[0])
    sys.exit(1)

  if len(sys.argv) < 2: usage()

  cmd = None
  args = []
  if sys.argv[1] == 'create':
    if len(sys.argv) not in (5,6): usage()
    if len(sys.argv) == 6:
      size=sys.argv[5]
    else:
      size = 0
    cmd = create
    args = (sys.argv[2], sys.argv[3], sys.argv[4], size)
  elif sys.argv[1] == 'init':
    if len(sys.argv) != 2: usage()
    sys.exit(init_key())
  elif sys.argv[1] == 'get':
    if len(sys.argv) != 4: usage()
    cmd = get
    args = (sys.argv[2], sys.argv[3])
  elif sys.argv[1] == 'change':
    if len(sys.argv) != 4: usage()
    cmd = change
    args = (sys.argv[2], sys.argv[3])
  elif sys.argv[1] == 'commit':
    if len(sys.argv) != 4: usage()
    cmd = commit
    args = (sys.argv[2], sys.argv[3])
  elif sys.argv[1] == 'delete':
    if len(sys.argv) != 4: usage()
    cmd = delete
    args = (sys.argv[2], sys.argv[3])
  elif sys.argv[1] == 'list':
    if len(sys.argv) != 3: usage()
    cmd = users
    args = (sys.argv[2],)
  elif sys.argv[1] == 'undo':
    if len(sys.argv) != 4: usage()
    cmd = undo
    args = (sys.argv[2],sys.argv[3])
  elif sys.argv[1] == 'backup':
    if len(sys.argv) != 2: usage()
    cmd = backup
    args = tuple()
  if cmd is not None:
    s = connect()
    if cmd not in (users,backup):
      pwd = sys.stdin.buffer.read()
      try:
        ret = cmd(s, pwd, *args)
      except:
        ret = False
        raise # todo remove only for dbg
      clearmem(pwd)
    else:
      try:
        ret = cmd(s,  *args)
      except:
        ret = False
        raise # todo remove only for dbg
    s.close()
    if not ret:
      print("fail")
      sys.exit(1)
  else:
    usage()

if __name__ == '__main__':
  main()
