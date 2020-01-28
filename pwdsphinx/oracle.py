#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2018, Marsiske Stefan 
# SPDX-License-Identifier: GPL-3.0-or-later

import socket, sys, ssl, os, datetime, binascii, pysodium, shutil, os.path
from SecureString import clearmem
from pwdsphinx import sphinxlib
from pwdsphinx.config import getcfg
cfg = getcfg('sphinx')

verbose = cfg['server'].getboolean('verbose')
address = cfg['server']['address']
port = int(cfg['server']['port'])
max_kids = int(cfg['server'].get('max_kids',5))
datadir = os.path.expanduser(cfg['server']['datadir'])
ssl_key = cfg['server']['ssl_key']
ssl_cert = cfg['server']['ssl_cert']

if(verbose):
  cfg.write(sys.stdout)

CREATE=0x00
READ=0x0f
BACKUP=0x33
UNDO=0x55
GET=0x66
COMMIT=0x99
CHANGE=0xaa
WRITE=0xcc
DELETE=0xff

def fail(s):
    if verbose: print('fail')
    s.send(b'fail') # plaintext :/
    s.close()
    os._exit(0)

def pop(obj, cnt):
  return obj[:cnt], obj[cnt:]

def verify_blob(msg, pk):
  sig = msg[-64:]
  msg = msg[:-64]
  pysodium.crypto_sign_verify_detached(sig, msg, pk)
  return msg

def save_blob(path,fname,blob):
  path = os.path.join(datadir, path, fname)
  with open(path,'wb') as fd:
    os.fchmod(fd.fileno(),0o600)
    fd.write(blob)

def update_blob(s):
    id = s.recv(32)
    if len(id)!=32:
      fail(s)
    id = binascii.hexlify(id).decode()
    blob = load_blob(id,'blob')
    new = False
    if blob is None:
      new = True
      blob = b'none'
    s.send(blob)
    blob = s.recv(8192) # todo/fixme arbitrary limit
    if new:
      pk = blob[:32]
      try:
        blob = verify_blob(blob,pk)
      except ValueError:
        print('invalid signature on msg')
        fail(s)
      blob = blob[32:]
      # create directories
      if not os.path.exists(datadir):
        os.mkdir(datadir,0o700)
      tdir = os.path.join(datadir,id)
      if not os.path.exists(tdir):
        os.mkdir(tdir,0o700)
      # save pubkey
      save_blob(id,'pub',pk)
    else:
      pk = load_blob(id,'pub')
      try:
        blob = verify_blob(blob,pk)
      except ValueError:
        print('invalid signature on msg')
        fail(s)
    save_blob(id,'blob',blob)

# msg format: 0x00|id[32]|alpha[32]
def create(s, msg):
    if len(msg)!=65:
      fail(s)
    op,   msg = pop(msg,1)
    id,   msg = pop(msg,32)
    alpha,msg = pop(msg,32)

    # 1st step OPRF with a new seed
    k=pysodium.randombytes(32)
    try:
        beta = sphinxlib.respond(alpha, k)
    except:
      fail(s)

    # check if id is unique
    id = binascii.hexlify(id).decode()
    tdir = os.path.join(datadir,id)
    if os.path.exists(tdir):
      if verbose: print("%s exists" % tdir)
      fail(s)

    s.send(beta)

    # wait for auth signing pubkey and rules
    msg = s.recv(32+50+64) # pubkey, rule, signature
    if len(msg)!=32+50+64:
      fail(s)
    # verify auth sig on packet
    pk = msg[0:32]
    try:
      msg = verify_blob(msg,pk)
    except ValueError:
      fail(s)

    rules = msg[32:]

    if not os.path.exists(datadir):
        os.mkdir(datadir,0o700)
    os.mkdir(tdir,0o700)

    save_blob(id,'key',k)
    save_blob(id,'pub',pk)
    save_blob(id,'rules',rules)

    # 3rd phase
    update_blob(s) # add user to host record
    update_blob(s) # also update root record with host hash
    s.send(b'ok')

def load_blob(path,fname,size=None):
    f = os.path.join(datadir,path,fname)
    if not os.path.exists(f):
        if verbose: print('%s does not exist' % f)
        return
    with open(f,'rb') as fd:
        v = fd.read()
    if size and len(v) != size:
        if verbose: print("wrong size for %s" % f)
        raise ValueError('corrupted blob: %s is not %s bytes' % (f, size))
    return v

# msg format: 0x66|id[32]|alpha[32]
def get(conn, msg):
    _, msg = pop(msg,1)
    id, msg = pop(msg,32)
    alpha, msg = pop(msg,32)
    if msg!=b'':
      if verbose: print('invalid get msg, trailing content %r' % msg)
      fail(conn)

    id = binascii.hexlify(id).decode()
    k = load_blob(id,'key',32)
    if k is None:
      # maybe execute protocol with static but random value to not leak which host ids exist?
      fail(conn)

    rules = load_blob(id,'rules', 50)
    if rules is None:
        fail(conn)

    try:
        beta = sphinxlib.respond(alpha, k)
    except:
      fail(conn)

    conn.send(beta+rules)

def auth(s,id,alpha):
  k = load_blob(id,'key')
  pk = load_blob(id,'pub',32)
  if pk is None:
    print('no pubkey found in %s' % id)
    return False
  try:
      beta = sphinxlib.respond(alpha, k)
  except:
    fail(conn)
  nonce=pysodium.randombytes(32)
  s.send(b''.join([beta,nonce]))
  sig = s.recv(64)
  try:
    pysodium.crypto_sign_verify_detached(sig, nonce, pk)
  except:
    return False
  return True

def change(conn, msg):
  op,   msg = pop(msg,1)
  id,   msg = pop(msg,32)
  alpha,msg = pop(msg,32)
  if msg!=b'':
    if verbose: print('invalid get msg, trailing content %r' % msg)
    fail(conn)

  id = binascii.hexlify(id).decode()
  tdir = os.path.join(datadir,id)
  if not os.path.exists(tdir):
    if verbose: print("%s doesn't exist" % tdir)
    fail(conn)

  if not auth(conn, id, alpha):
    fail(conn)

  k=pysodium.randombytes(32)

  try:
      beta = sphinxlib.respond(alpha, k)
  except:
    fail(conn)

  #print("beta=",beta.hex())
  rules = load_blob(id,'rules', 50)
  if rules is None:
      fail(conn)

  save_blob(id,'new',k)
  conn.send(beta+rules)

def commit(conn, msg):
  # todo auth?
  op,   msg = pop(msg,1)
  id,   msg = pop(msg,32)
  alpha,msg = pop(msg,32)
  if msg!=b'':
    if verbose: print('invalid get msg, trailing content %r' % msg)
    fail(conn)

  id = binascii.hexlify(id).decode()
  tdir = os.path.join(datadir,id)
  if not os.path.exists(tdir):
    if verbose: print("%s doesn't exist" % tdir)
    fail(conn)

  if not auth(conn, id, alpha):
    fail(conn)

  k = load_blob(id,'new', 32)
  if k is None:
      fail(conn)

  old = load_blob(id,'key', 32)
  if old is None:
      fail(conn)

  try:
      beta = sphinxlib.respond(alpha, k)
  except:
    fail(conn)

  rules = load_blob(id,'rules', 50)
  if rules is None:
      fail(conn)

  conn.send(beta+rules)

  blob = conn.recv(32+50+64)
  if len(blob)!=32+50+64:
    fail(conn)

  pk = blob[0:32]
  try:
    blob = verify_blob(blob,pk)
  except ValueError:
    fail(s)
  rules = blob[32:]

  save_blob(id,'old',old)
  save_blob(id,'key',k)
  save_blob(id,'pub',pk)
  save_blob(id,'rules',rules)
  os.unlink(os.path.join(tdir,'new'))
  conn.send(b'ok')

def undo(conn, msg):
  # todo auth?
  op,   msg = pop(msg,1)
  id,   msg = pop(msg,32)
  alpha,msg = pop(msg,32)
  if msg!=b'':
    if verbose: print('invalid get msg, trailing content %r' % msg)
    fail(conn)

  id = binascii.hexlify(id).decode()
  tdir = os.path.join(datadir,id)
  if not os.path.exists(tdir):
    if verbose: print("%s doesn't exist" % tdir)
    fail(conn)

  if not auth(conn, id, alpha):
    fail(conn)

  k = load_blob(id,'old', 32)
  if k is None:
      fail(conn)

  new = load_blob(id,'key', 32)
  if new is None:
      fail(conn)

  try:
      beta = sphinxlib.respond(alpha, k)
  except:
    fail(conn)

  rules = load_blob(id,'rules', 50)
  if rules is None:
      fail(conn)

  conn.send(beta+rules)

  blob = conn.recv(32+50+64)
  if len(blob)!=32+50+64:
    fail(conn)

  pk = blob[0:32]
  try:
    blob = verify_blob(blob,pk)
  except ValueError:
    fail(s)
  rules = blob[32:]

  save_blob(id,'new',new)
  save_blob(id,'key',k)
  save_blob(id,'pub',pk)
  save_blob(id,'rules',rules)
  os.unlink(os.path.join(tdir,'old'))
  conn.send(b'ok')

#### here be dragons ####

def read(conn, msg):
  # todo auth?
  _, msg = pop(msg,1)
  id, msg = pop(msg,32)
  id = binascii.hexlify(id).decode()

  blob = load_blob(id,'blob')
  if blob is None:
    blob = b''

  conn.send(blob)

def write(conn, msg):
  # todo auth?
  op,msg = pop(msg,1)
  pk1,msg = pop(msg,32)
  id,blob = pop(msg,32)
  id = binascii.hexlify(id).decode()

  pk0 = load_blob(id,'pub')
  if pk0 and pk0 != pk1:
    fail(conn)

  if not os.path.exists(datadir):
    os.mkdir(datadir,0o700)
  tdir = os.path.join(datadir,id)
  if not os.path.exists(tdir):
    os.mkdir(tdir,0o700)
  save_blob(id,'blob',blob)
  if pk0 is None:
    save_blob(id,'pub',pk1)
  conn.send(b'ok')

def delete(conn, msg):
  # todo auth?
  op,   msg = pop(msg,1)
  id,   msg = pop(msg,32)
  if msg!=b'':
    if verbose: print('invalid get msg, trailing content %r' % msg)
    fail(conn)

  id = binascii.hexlify(id).decode()
  tdir = os.path.join(datadir,id)
  if not os.path.exists(tdir):
    if verbose: print("%s doesn't exist" % tdir)
    fail(conn)
  shutil.rmtree(tdir)
  conn.send(b'ok')
  # todo implement updating user and root record

def handler(conn):
   data = conn.recv(4096)
   if verbose:
     print('Data received: {!r}'.format(data))

   if data[0] == CREATE:
     create(conn, data)
   elif data[0] == GET:
     get(conn, data)
   elif data[0] == CHANGE:
     change(conn, data)
   elif data[0] == DELETE:
     delete(conn, data)
   elif data[0] == COMMIT:
     commit(conn, data)
   elif data[0] == UNDO:
     undo(conn, data)
   elif data[0] == BACKUP:
     backup(conn, data)
   elif data[0] == READ:
     read(conn, data)
   elif data[0] == WRITE:
     write(conn, data)
   elif verbose:
     print("unknown op: 0x%02x" % data[0])

   conn.close()
   os._exit(0)

def main():
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=ssl_cert, keyfile=ssl_key)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((address, port))
    except socket.error as msg:
        print('Bind failed. Error Code : %s Message: ' % (str(msg[0]), msg[1]))
        sys.exit()
    #Start listening on socket
    s.listen()
    kids = []
    try:
        # main loop
        while 1:
            #wait to accept a connection - blocking call
            conn, addr = s.accept()
            if verbose:
                print('{} Connection from {}:{}'.format(datetime.datetime.now(), addr[0], addr[1]))
            conn = ctx.wrap_socket(conn, server_side=True)

            while(len(kids)>max_kids):
                pid, status = os.waitpid(0,0)
                kids.remove(pid)

            pid=os.fork()
            if pid==0:
              ssl.RAND_add(os.urandom(16),0.0)
              try:
                handler(conn)
              finally:
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
            else:
                kids.append(pid)

            pid, status = os.waitpid(0,os.WNOHANG)
            if(pid,status)!=(0,0):
                kids.remove(pid)

    except KeyboardInterrupt:
        pass
    s.close()

if __name__ == '__main__':
  main()
