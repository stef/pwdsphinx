#!/usr/bin/env python3

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

# msg format: 0x00|pk[32]|id[32]|alpha[32]|rule[50]|sig[64]
def create(conn, msg):
    op,   msg = pop(msg,1)
    pk,   msg = pop(msg,32)
    id,   msg = pop(msg,32)
    alpha,msg = pop(msg,32)
    rules,msg = pop(msg,50)
    if msg!=b'':
      if verbose: print('invalid get msg, trailing content %r' % msg)
      fail(conn)
      return

    id = binascii.hexlify(id).decode()
    tdir = os.path.join(datadir,id)
    if os.path.exists(tdir):
      if verbose: print("%s exists" % tdir)
      fail(conn)
      return

    k=pysodium.randombytes(32)

    try:
        beta = sphinxlib.respond(alpha, k)
    except:
      fail(conn)
      return

    if not os.path.exists(datadir):
        os.mkdir(datadir,0o700)
    os.mkdir(tdir,0o700)

    save_blob(id,'key',k)
    save_blob(id,'pub',pk)
    save_blob(id,'rules',rules)

    conn.send(beta)

def load_blob(path,fname,size=None):
    f = os.path.join(datadir,path,fname)
    if not os.path.exists(f):
        if verbose: print('%s does not exist' % f)
        return
    with open(f,'rb') as fd:
        v = fd.read()
    if size and len(v) != size:
        if verbose: print("wrong size for %s" % f)
        return
    return v

# msg format: 0x66|id[32]|alpha[32]
def get(conn, msg):
    _, msg = pop(msg,1)
    id, msg = pop(msg,32)
    alpha, msg = pop(msg,32)
    if msg!=b'':
      if verbose: print('invalid get msg, trailing content %r' % msg)
      fail(conn)
      return

    id = binascii.hexlify(id).decode()
    k = load_blob(id,'key',32)
    if k is None:
      # maybe execute protocol with static but random value to not leak which host ids exist?
      fail(conn)
      return

    rules = load_blob(id,'rules', 50)
    if rules is None:
        fail(conn)
        return

    try:
        beta = sphinxlib.respond(alpha, k)
    except:
      fail(conn)
      return

    conn.send(beta+rules)

def auth(msg):
    id = binascii.hexlify(msg[1:33]).decode()
    pk = load_blob(id,'pub',32)
    if pk is None:
      print('no pubkey found in %s' % id)
      return
    try:
      msg = verify_blob(msg,pk)
    except ValueError:
      print('invalid signature on msg')
      return
    return msg

def read(conn, msg):
  _, msg = pop(msg,1)
  id, msg = pop(msg,32)
  id = binascii.hexlify(id).decode()

  blob = load_blob(id,'blob')
  if blob is None:
    blob = b''

  conn.send(blob)

def write(conn, msg):
  op,msg = pop(msg,1)
  pk1,msg = pop(msg,32)
  id,blob = pop(msg,32)
  id = binascii.hexlify(id).decode()

  pk0 = load_blob(id,'pub')
  if pk0 and pk0 != pk1:
    fail(conn)
    return

  if not os.path.exists(datadir):
    os.mkdir(datadir,0o700)
  tdir = os.path.join(datadir,id)
  if not os.path.exists(tdir):
    os.mkdir(tdir,0o700)
  save_blob(id,'blob',blob)
  if pk0 is None:
    save_blob(id,'pub',pk1)
  conn.send(b'ok')

def change(conn, msg):
  op,   msg = pop(msg,1)
  id,   msg = pop(msg,32)
  alpha,msg = pop(msg,32)
  #print("alpha=",alpha.hex())
  if msg!=b'':
    if verbose: print('invalid get msg, trailing content %r' % msg)
    fail(conn)
    return

  id = binascii.hexlify(id).decode()
  tdir = os.path.join(datadir,id)
  if not os.path.exists(tdir):
    if verbose: print("%s doesn't exist" % tdir)
    fail(conn)
    return

  k=pysodium.randombytes(32)
  #print("k=",k.hex())

  try:
      beta = sphinxlib.respond(alpha, k)
  except:
    fail(conn)
    return

  #print("beta=",beta.hex())
  rules = load_blob(id,'rules', 50)
  if rules is None:
      fail(conn)
      return

  save_blob(id,'new',k)
  conn.send(beta+rules)

def commit(conn, msg):
  op,   msg = pop(msg,1)
  id,   msg = pop(msg,32)
  alpha,msg = pop(msg,32)
  #print("alpha=",alpha.hex())
  if msg!=b'':
    if verbose: print('invalid get msg, trailing content %r' % msg)
    fail(conn)
    return

  id = binascii.hexlify(id).decode()
  tdir = os.path.join(datadir,id)
  if not os.path.exists(tdir):
    if verbose: print("%s doesn't exist" % tdir)
    fail(conn)
    return

  k = load_blob(id,'new', 32)
  if k is None:
      fail(conn)
      return

  old = load_blob(id,'key', 32)
  if old is None:
      fail(conn)
      return

  try:
      beta = sphinxlib.respond(alpha, k)
  except:
    fail(conn)
    return

  #print("beta=",beta.hex())
  rules = load_blob(id,'rules', 50)
  if rules is None:
      fail(conn)
      return

  save_blob(id,'old',old)
  save_blob(id,'key',k)
  os.unlink(os.path.join(tdir,'new'))

  conn.send(beta+rules)

def undo(conn, msg):
  op,   msg = pop(msg,1)
  id,   msg = pop(msg,32)
  alpha,msg = pop(msg,32)
  #print("alpha=",alpha.hex())
  if msg!=b'':
    if verbose: print('invalid get msg, trailing content %r' % msg)
    fail(conn)
    return

  id = binascii.hexlify(id).decode()
  tdir = os.path.join(datadir,id)
  if not os.path.exists(tdir):
    if verbose: print("%s doesn't exist" % tdir)
    fail(conn)
    return

  k = load_blob(id,'old', 32)
  if k is None:
      fail(conn)
      return

  new = load_blob(id,'key', 32)
  if new is None:
      fail(conn)
      return

  try:
      beta = sphinxlib.respond(alpha, k)
  except:
    fail(conn)
    return

  #print("beta=",beta.hex())
  rules = load_blob(id,'rules', 50)
  if rules is None:
      fail(conn)
      return

  save_blob(id,'new',new)
  save_blob(id,'key',k)
  os.unlink(os.path.join(tdir,'old'))

  conn.send(beta+rules)

def delete(conn, msg):
  op,   msg = pop(msg,1)
  id,   msg = pop(msg,32)
  if msg!=b'':
    if verbose: print('invalid get msg, trailing content %r' % msg)
    fail(conn)
    return

  id = binascii.hexlify(id).decode()
  tdir = os.path.join(datadir,id)
  if not os.path.exists(tdir):
    if verbose: print("%s doesn't exist" % tdir)
    fail(conn)
    return
  shutil.rmtree(tdir)
  conn.send(b'ok')

def handler(conn):
   data = conn.recv(4096)
   if verbose:
     print('Data received: {!r}'.format(data))

   # check auth
   if data[0] in (READ,CHANGE,COMMIT,UNDO,DELETE,BACKUP):
     data = auth(data)
     if data is None:
        fail(conn)
        conn.close()
        os._exit(0)
   elif data[0] in (CREATE,WRITE):
     pk = data[1:33]
     try:
       data = verify_blob(data,pk)
     except ValueError:
       fail(conn)
       conn.close()
       os._exit(0)

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
