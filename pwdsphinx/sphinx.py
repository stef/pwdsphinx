#!/usr/bin/env python3

import sys, os, socket, io, struct, binascii, platform, ssl
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

cfg = getcfg('sphinx')

verbose = cfg['client'].getboolean('verbose')
address = cfg['client']['address']
port = int(cfg['client']['port'])
datadir = os.path.expanduser(cfg['client']['datadir'])
ssl_cert = cfg['client']['ssl_cert'] # TODO only for dev, production system should use proper certs!

CREATE   =b'\x00' # sphinx
READ     =b'\x33' # blob
UNDO     =b'\x55' # change sphinx
GET      =b'\x66' # sphinx
COMMIT   =b'\x99' # change sphinx
CHANGE   =b'\xaa' # sphinx
WRITE    =b'\xcc' # blob
DELETE   =b'\xff' # sphinx+blobs

ENC_CTX = b"sphinx encryption key"
SALT_CTX = b"sphinx host salt"
BLOB_CTX = b"sphinx blob salt"
ROOT_CTX = b"sphinx root idx"
PASS_CTX = b"sphinx password context"

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
  ctx.load_verify_locations(ssl_cert) # TODO only for dev, production system should use proper certs!
  ctx.check_hostname=False            # TODO only for dev, production system should use proper certs!
  ctx.verify_mode=ssl.CERT_NONE       # TODO only for dev, production system should use proper certs!

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s = ctx.wrap_socket(s)
  s.connect((address, port))
  return s

def getrootid():
  mk = get_masterkey()
  root = pysodium.crypto_generichash(ROOT_CTX, mk)
  clearmem(mk)
  return root

def getid(host, user, ctx = SALT_CTX):
  mk = get_masterkey()
  salt = pysodium.crypto_generichash(ctx, mk)
  clearmem(mk)
  return pysodium.crypto_generichash(b'|'.join((user.encode(),host.encode())), salt, 32)

def getlocalkey():
  mk = get_masterkey()
  key = pysodium.crypto_generichash(ENC_CTX, mk)
  clearmem(mk)
  return key

def unpack_rule(rules):
  rule = struct.unpack(">H",rules)[0]
  size = (rule & 0x7f)
  rule = {c for i,c in enumerate(('u','l','s','d')) if (rule >> 7) & (1 << i)}
  return rule, size

def pack_rule(char_classes, size):
  # pack rules into 2 bytes
  if set(char_classes) - {'u','l','s','d'}:
    raise ValueError("error: rules can only contain any of 'ulsd'.")

  rules = sum(1<<i for i, c in enumerate(('u','l','s','d')) if c in char_classes)
  # pack rule
  return struct.pack('>H', (rules << 7) | (size & 0x7f))

def _get(s, pwd, user, host, cmd, rwd):
   pub, sec = sphinxlib.opaque_session_usr_start(pwd)
   msg = b''.join([cmd, getid(host, user, BLOB_CTX if cmd in {READ,WRITE} else SALT_CTX), pub])
   s.send(msg)
   resp = s.recv(4096)
   if resp == b'fail' or len(resp) < sphinxlib.OPAQUE_SERVER_SESSION_LEN:
      print("opaque_server_session failed")
      return
   return sphinxlib.opaque_session_usr_finish(pwd, resp, sec, getlocalkey(), rwd)

def _create(s, pwd, user, host, extra, cmd = CREATE):
  rwd = None
  r, alpha = sphinxlib.opaque_private_init_usr_start(pwd)

  msg = b''.join([cmd, getid(host, user, BLOB_CTX if cmd == WRITE else SALT_CTX), alpha])
  s.send(msg)
  resp = s.recv(4096)
  rec, rwd = sphinxlib.opaque_private_init_usr_respond(pwd, r, resp, extra, getlocalkey(), rwd=True)
  s.send(rec)
  resp = s.recv(4096)
  if(resp==b'ok'):
    return rwd
  if rwd: clearmem(rwd)

def _change(s, pwd, extra, rwd=False):
  try:
    r, alpha = sphinxlib.opaque_private_init_usr_start(pwd)
    s.send(alpha)

    resp = s.recv(4096)
    rec = sphinxlib.opaque_private_init_usr_respond(pwd, r, resp, extra, getlocalkey(), rwd)
    if rwd:
        rec, rwd = rec
    s.send(rec)

    resp = s.recv(4096)
    if resp==b"ok":
      return rwd or True
    return False
  except:
    return False

def auth(s, pwd, user, host, op):
   ret = _get(s, pwd, user, host, op, False)
   if not ret: return
   sk, extra = ret
   auth = sphinxlib.opaque_f(sk, 2)
   clearmem(sk)
   s.send(auth)
   return extra

def update_record(s,pwd,user,host,op,blob = None):
   extra = auth(s, pwd, '' if op != WRITE else user, host, op)
   if extra is None:
     return False

   if op == WRITE:
     extra = blob
   else:
     users = set(extra.decode().split('\n'))
     if op == CREATE:
       users.add(user)
     elif op == DELETE:
        if not user in users:
          print("%s not found in user record" % user)
          return False
        users.remove(user)
     extra = '\n'.join(sorted(users)).encode()
   return _change(s, pwd, extra, False)

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

def create(s, pwd, user, host, classes, size=0):
    rule = pack_rule(classes, size)
    rwd = _create(s, pwd, user, host, rule)
    if(not rwd):
      return
    rpwd = bin2pass.derive(pysodium.crypto_generichash(PASS_CTX, rwd),classes,size).decode()
    clearmem(rwd)
    print(rpwd)
    clearmem(rpwd)

    blob = user.encode()
    # upsert user
    msg = b''.join([WRITE,getid(host,'')])
    s.send(msg)

    rec = s.recv(1) # todo fixme arbitrary limit
    if rec == b'\x00':
       # create new user record
       rwd = _create(s, pwd, '', host, blob)
       if rwd:
         clearmem(rwd)
         return True
       else:
         print("failed to create new user record")
    elif rec == b'\xff':
       # update existing user record
      return update_record(s,pwd,user,host,CREATE)
    else:
       print("invalid response when trying to upsert user")
    return False

def get(s, pwd, user, host):
    ret = _get(s, pwd, user, host, GET, True)
    if not ret:
        return
    sk, extra, rwd = ret
    clearmem(sk)
    classes, size = unpack_rule(extra)
    rpwd = bin2pass.derive(pysodium.crypto_generichash(PASS_CTX, rwd),classes,size).decode()
    clearmem(rwd)
    print(rpwd)
    clearmem(rpwd)
    return True

def users(s, pwd, host):
    res = _get(s, pwd, '' , host, GET, False)
    if not res: return
    sk, extra = res
    clearmem(sk)
    print('\n'.join(extra.decode().split('\n')))
    return True

def delete(s, pwd, user, host):
    ret = auth(s, pwd, user, host, DELETE)
    if ret is None:
      return False

    # change user record
    return update_record(s,pwd,user,host,DELETE)

def change(s, pwd, user, host):
    rule = auth(s, pwd, user, host, CHANGE)
    if rule is None:
      return False

    rwd = _change(s, pwd, rule, rwd = True)
    if not rwd:
      return
    classes, size = unpack_rule(rule)
    rpwd = bin2pass.derive(pysodium.crypto_generichash(PASS_CTX, rwd),classes,size).decode()
    clearmem(rwd)
    print(rpwd)
    clearmem(rpwd)
    return True

def commit_undo(s, pwd, type, user, host):
    ret = auth(s, pwd, user, host, type)
    if ret is None:
      return False

    resp =  s.recv(4096)
    if(resp!=b'ok'):
        return
    return get(s,pwd,user,host)

def write(s, blob, user, host):
   pwd, blob = blob.decode().split('\n',1)
   # goddamn fucking py3 with it's braindead string/bytes smegma shit may hastur haunt the dreams and cthulhu chew on the soul whoever came up with this retardedness
   pwd = pwd.encode()
   blob = blob.encode()

   msg = b''.join([WRITE, getid(host, user, BLOB_CTX)])
   s.send(msg)

   exists = s.recv(1)
   if exists == b'\x00':
      rwd = _create(s, pwd, user, host, blob, cmd = WRITE)
      if rwd:
        clearmem(rwd)
        return True
      else:
        print("failed to create new blob")
   elif exists == b'\xff':
      # update existing user record
     return update_record(s,pwd,user,host,WRITE,blob)
   else:
      print("invalid response when checking existance of record")
   return False

def read(s, pwd, user, host):
   ret = _get(s, pwd, user, host, READ, True)
   if not ret:
       return False
   sk, extra, rwd = ret
   clearmem(sk)
   clearmem(rwd)
   print(extra)
   return True

def main():
  def usage():
    print("usage: %s init" % sys.argv[0])
    print("usage: %s create <user> <site> [u][l][d][s] [<size>]" % sys.argv[0])
    print("usage: %s <get|change|commit|delete> <user> <site>" % sys.argv[0])
    print("usage: %s <write|read> [user] <site>" % sys.argv[0])
    print("usage: %s list <site>" % sys.argv[0])
    sys.exit(1)

  if len(sys.argv) < 2: usage()

  cmd = None
  args = []
  if sys.argv[1] == 'create':
    if len(sys.argv) not in (5,6): usage()
    if len(sys.argv) == 6:
      size=int(sys.argv[5])
    else:
      size = 0
    cmd = create
    args = (sys.argv[2], sys.argv[3], sys.argv[4], size)
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
    cmd = commit_undo
    args = (COMMIT, sys.argv[2], sys.argv[3])
  elif sys.argv[1] == 'undo':
    if len(sys.argv) != 4: usage()
    cmd = commit_undo
    args = (UNDO, sys.argv[2], sys.argv[3])
  elif sys.argv[1] == 'delete':
    if len(sys.argv) != 4: usage()
    cmd = delete
    args = (sys.argv[2], sys.argv[3])
  elif sys.argv[1] == 'list':
    if len(sys.argv) != 3: usage()
    cmd = users
    args = (sys.argv[2],)
  elif sys.argv[1] == 'write':
    if len(sys.argv) not in (3,4): usage()
    if len(sys.argv) == 4:
      user=sys.argv[2]
      host=sys.argv[3]
    else:
      user = ''
      host=sys.argv[2]
    cmd = write
    args = (user, host)
  elif sys.argv[1] == 'read':
    if len(sys.argv) not in (3,4): usage()
    if len(sys.argv) == 4:
      user=sys.argv[2]
      host=sys.argv[3]
    else:
      user = ''
      host=sys.argv[2]
    cmd = read
    args = (user, host)

  if cmd is not None:
    s = connect()
    pwd = sys.stdin.buffer.read()
    ret = cmd(s, pwd, *args)
    clearmem(pwd)
    s.close()
    if not ret:
      print("fail")
      sys.exit(1)
  else:
    usage()

  return ret

if __name__ == '__main__':
  main()
