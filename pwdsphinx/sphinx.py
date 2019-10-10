#!/usr/bin/env python3

import sys, os, socket, io, struct, binascii, platform
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
datadir = cfg['client']['datadir']

CREATE=b'\x00'
GET=b'\x66'
COMMIT=b'\x99'
CHANGE=b'\xaa'
DELETE=b'\xff'

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((address, port))
    return s

def getsalt():
  path = os.path.expanduser(datadir)
  try:
    fd = open(path+'salt', 'rb')
    salt = fd.read()
    fd.close()
    return salt
  except FileNotFoundError:
    print("Could not find salt! If sphinx was working previously it is now broken.\nIf this is a fresh install all is good, we just create a new salt for you.")
    if not os.path.exists(path):
      os.mkdir(path,0o700)
    salt = pysodium.randombytes(32)
    with open(path+'salt','wb') as fd:
      if not win: os.fchmod(fd.fileno(),0o600)
      fd.write(salt)
    return salt

def getid(host, user):
    salt = getsalt()
    return pysodium.crypto_generichash(b''.join((user.encode(),host.encode())), salt, 32)

def getserverkey():
  path = os.path.expanduser(datadir)
  try:
    with open(path+'server-key.pub', 'rb') as fd:
      key = fd.read()
    return key
  except FileNotFoundError:
    pass
  # try in installation dir
  BASEDIR = os.path.dirname(os.path.abspath(__file__))
  try:
    with open(BASEDIR+'/server-key.pub', 'rb') as fd:
      key = fd.read()
    return key
  except FileNotFoundError:
    print("no server key found, please install it")
    sys.exit(1)

def unpack_rule(rules):
    rule = struct.unpack(">H",rules)[0]
    size = (rule & 0x7f)
    rule = {c for i,c in enumerate(('u','l','s','d')) if (rule >> 7) & (1 << i)}
    return rule, size

def _create(s, pwd, user, host, extra):
    r, alpha = sphinxlib.opaque_private_init_usr_start(pwd)

    msg = b''.join([CREATE, getid(host, user), alpha])
    pk = getserverkey()
    sealed = pysodium.crypto_box_seal(msg,pk)
    s.send(sealed)
    resp = s.recv(4096)
    rec, rwd = sphinxlib.opaque_private_init_usr_respond(pwd, r, resp, extra, rwd=True)
    s.send(rec)
    resp = s.recv(4096)
    return resp, rwd

# this essentially creates an opaque record with a '' user, but the extra data contains the list of users that have an account on this host
# what it does, it tries to call a change() on the (pwd,'',host) triple, if if this fails it tries a create(), otherwise it also implements a commit()
# todo somehow refactor this so that we do not duplicate large parts of create/change/commit
def upsert_user(s, pwd, user, host):
    # change
    res = _get(s, pwd, '', host, CHANGE)
    if not res:
        # create
        extra = user.encode()
        s.close()
        s=connect()
        try:
            resp, rwd = _create(s, pwd, '', host, extra)
        except:
            print('fail')
            return
        finally:
            clearmem(rwd)

        if(resp!=b'ok'): # instead of plaintext fail/ok maye just run a GET to check if the rwd returned == the rwd we have established here?
            print("fail")
        return

    sk, extra, rwd = res
    clearmem(rwd)
    users = set(extra.decode().split('\n'))
    users.add(user)
    extra = '\n'.join(sorted(users)).encode()

    r, alpha = sphinxlib.opaque_private_init_usr_start(pwd)

    # implicit authentication by using an encrypted channel
    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    msg = pysodium.crypto_secretbox(alpha,nonce,sk)
    s.send(nonce+msg)

    msg = s.recv(4096)
    try:
        resp = pysodium.crypto_secretbox_open(msg[pysodium.crypto_secretbox_NONCEBYTES:],msg[:pysodium.crypto_secretbox_NONCEBYTES],sk)
    except:
        clearmem(sk)
        print("fail")
        return

    rec = sphinxlib.opaque_private_init_usr_respond(pwd, r, resp, extra)
    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    msg = pysodium.crypto_secretbox(rec,nonce,sk)
    s.send(nonce+msg)

    msg = s.recv(4096)
    try:
        resp = pysodium.crypto_secretbox_open(msg[pysodium.crypto_secretbox_NONCEBYTES:],msg[:pysodium.crypto_secretbox_NONCEBYTES],sk)
    except:
        print("fail")
        return
    finally:
        clearmem(sk)

    if(resp!=b'ok'):
        print("fail")
        return

    # commit
    s.close()
    s=connect()
    res = _get(s, pwd, '', host, COMMIT)
    if not res:
        print("fail")
        return
    sk, extra, rwd = res
    clearmem(rwd)
    auth = sphinxlib.opaque_f(sk, 2)
    s.send(auth)

    msg = s.recv(4096)
    try:
        resp = pysodium.crypto_secretbox_open(msg[pysodium.crypto_secretbox_NONCEBYTES:],msg[:pysodium.crypto_secretbox_NONCEBYTES],sk)
    except:
        print("fail")
        return
    finally:
        clearmem(sk)

    if(resp!=b'ok'):
        print('fail')


def users(s, pwd, host):
    res = _get(s, pwd, '' , host, GET)
    if not res: return
    sk, extra, rwd = res
    clearmem(sk)
    clearmem(rwd)
    print(repr(extra))
    print(extra.decode().split('\n'))

def create(s, pwd, user, host, char_classes, size=0):
    if set(char_classes) - {'u','l','s','d'}:
      raise ValueError("error: rules can only contain ulsd.")
    try: size=int(size)
    except:
      raise ValueError("error: size has to be integer.")

    rules = sum(1<<i for i, c in enumerate(('u','l','s','d')) if c in char_classes)
    # pack rule
    rule=struct.pack('>H', (rules << 7) | (size & 0x7f))

    try:
        resp, rwd = _create(s, pwd, user, host, rule)
    except:
        print('fail')
        return

    if(resp==b'ok'): # instead of plaintext fail/ok maybe just run a GET to check if the rwd returned == the rwd we have established here?
        print(bin2pass.derive(rwd,char_classes,size).decode())
        s.close()
        s=connect()
        upsert_user(s, pwd, user, host)
    else:
        print("fail")

def _get(s, pwd, user, host, cmd):
    pub, sec = sphinxlib.opaque_session_usr_start(pwd)
    msg = b''.join([cmd, getid(host, user), pub])
    pk = getserverkey()
    sealed = pysodium.crypto_box_seal(msg,pk)
    s.send(sealed)
    resp = s.recv(4096)
    if resp == b'fail' or len(resp) < sphinxlib.OPAQUE_SERVER_SESSION_LEN:
        return
    sk, extra, rwd = sphinxlib.opaque_session_usr_finish(pwd, resp, sec, True)
    return sk, extra, rwd

def get(s, pwd, user, host):
    ret = _get(s, pwd, user, host, GET)
    if not ret:
        print("fail")
        return
    sk, extra, rwd = ret
    clearmem(sk)
    classes, size = unpack_rule(extra)
    print(bin2pass.derive(rwd,classes,size).decode())
    clearmem(rwd)

def delete(s, pwd, user, host):
    res = _get(s, pwd, user, host, DELETE)
    if not res: return
    sk, extra, rwd = res
    clearmem(rwd)
    auth = sphinxlib.opaque_f(sk, 2)
    s.send(auth)

    msg = s.recv(4096)
    try:
        resp = pysodium.crypto_secretbox_open(msg[pysodium.crypto_secretbox_NONCEBYTES:],msg[:pysodium.crypto_secretbox_NONCEBYTES],sk)
    except:
        print("fail")
        return
    finally:
        clearmem(sk)

    if(resp==b'ok'):
        print("deleted")
        # todo implement delete user from user list
    else:
        print("fail")

def change(s, pwd, user, host):
    res = _get(s, pwd, user, host, CHANGE)
    if not res: return
    sk, rule, rwd = res
    clearmem(rwd)

    r, alpha = sphinxlib.opaque_private_init_usr_start(pwd)

    # implicit authentication by using an encrypted channel
    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    msg = pysodium.crypto_secretbox(alpha,nonce,sk)
    s.send(nonce+msg)

    msg = s.recv(4096)
    try:
        resp = pysodium.crypto_secretbox_open(msg[pysodium.crypto_secretbox_NONCEBYTES:],msg[:pysodium.crypto_secretbox_NONCEBYTES],sk)
    except:
        clearmem(sk)
        print("fail")
        return

    rec, rwd = sphinxlib.opaque_private_init_usr_respond(pwd, r, resp, rule, rwd=True)
    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    msg = pysodium.crypto_secretbox(rec,nonce,sk)
    s.send(nonce+msg)

    msg = s.recv(4096)
    try:
        resp = pysodium.crypto_secretbox_open(msg[pysodium.crypto_secretbox_NONCEBYTES:],msg[:pysodium.crypto_secretbox_NONCEBYTES],sk)
    except:
        print("fail")
        return
    finally:
        clearmem(sk)

    if(resp==b'ok'):
        classes, size = unpack_rule(rule)
        print(bin2pass.derive(rwd,classes,size).decode())
    else:
        print("fail")
    clearmem(rwd)

def commit(s, pwd, user, host):
    res = _get(s, pwd, user, host, COMMIT)
    if not res: return
    sk, extra, rwd = res
    clearmem(rwd)
    auth = sphinxlib.opaque_f(sk, 2)
    s.send(auth)

    msg = s.recv(4096)
    try:
        resp = pysodium.crypto_secretbox_open(msg[pysodium.crypto_secretbox_NONCEBYTES:],msg[:pysodium.crypto_secretbox_NONCEBYTES],sk)
    except:
        print("fail")
        return
    finally:
        clearmem(sk)

    if(resp==b'ok'):
        s.close()
        s=connect()
        get(s,pwd,user,host)
    else:
        print("fail")

def main():
  def usage():
    print("usage: %s create <user> <site> [u][l][d][s] [<size>]" % sys.argv[0])
    print("usage: %s <get|change|commit|delete> <user> <site>" % sys.argv[0])
    print("usage: %s list <site>" % sys.argv[0])
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
  if cmd is not None:
    s = connect()
    pwd = sys.stdin.buffer.read()
    cmd(s, pwd, *args)
    s.close()
  else:
    usage()

if __name__ == '__main__':
  main()
