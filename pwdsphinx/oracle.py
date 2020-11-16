#!/usr/bin/env python3

import socket, sys, ssl, os, datetime, binascii, shutil, os.path, traceback
import pysodium
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
READ=0x33
UNDO=0x55
GET=0x66
COMMIT=0x99
CHANGE=0xaa
WRITE=0xcc
DELETE=0xff

RULE_SIZE=42

def fail(s):
    if verbose:
        traceback.print_stack()
        print('fail')
    s.send(b'\x00\x04fail') # plaintext :/
    s.shutdown(socket.SHUT_RDWR)
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
      blob = b'\x00\x00'
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

    # check if id is unique
    id = binascii.hexlify(id).decode()
    tdir = os.path.join(datadir,id)
    if(os.path.exists(os.path.join(tdir,'rules'))):
      fail(s)

    # 1st step OPRF with a new seed
    # this might be if the user already has stored a blob for this id
    # and now also wants a sphinx rwd
    if(os.path.exists(os.path.join(tdir,'key'))):
      k = load_blob(id,'key',32)
    else:
      k=pysodium.randombytes(32)
    try:
        beta = sphinxlib.respond(alpha, k)
    except:
      fail(s)

    s.send(beta)

    # wait for auth signing pubkey and rules
    msg = s.recv(32+RULE_SIZE+64) # pubkey, rule, signature
    if len(msg)!=32+RULE_SIZE+64:
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
    if not os.path.exists(tdir):
        os.mkdir(tdir,0o700)

    save_blob(id,'key',k)
    save_blob(id,'pub',pk)
    save_blob(id,'rules',rules)

    # 3rd phase
    update_blob(s) # add user to host record
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

    rules = load_blob(id,'rules', RULE_SIZE)
    if rules is None:
        fail(conn)

    try:
        beta = sphinxlib.respond(alpha, k)
    except:
      fail(conn)

    conn.send(beta+rules)

def auth(s,id,alpha):
  pk = load_blob(id,'pub',32)
  if pk is None:
    print('no pubkey found in %s' % id)
    fail(s)
  nonce=pysodium.randombytes(32)
  k = load_blob(id,'key')
  if k is not None:
    try:
       beta = sphinxlib.respond(alpha, k)
    except:
       fail(s)
  else:
    beta = b''
  s.send(b''.join([beta,nonce]))
  sig = s.recv(64)
  try:
    pysodium.crypto_sign_verify_detached(sig, nonce, pk)
  except:
    print('bad sig')
    fail(s)

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

  auth(conn, id, alpha)

  k=pysodium.randombytes(32)

  try:
      beta = sphinxlib.respond(alpha, k)
  except:
    fail(conn)

  #print("beta=",beta.hex())
  rules = load_blob(id,'rules', RULE_SIZE)
  if rules is None:
      fail(conn)

  save_blob(id,'new',k)
  conn.send(beta+rules)

def delete(conn, msg):
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

  auth(conn, id, alpha)

  update_blob(conn)

  shutil.rmtree(tdir)
  conn.send(b'ok')

def commit_undo(conn, msg, new, old):
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

  auth(conn, id, alpha)

  k = load_blob(id,new, 32)
  if k is None:
      fail(conn)

  key = load_blob(id,'key', 32)
  if key is None:
      fail(conn)

  try:
      beta = sphinxlib.respond(alpha, k)
  except:
    fail(conn)

  rules = load_blob(id,'rules', RULE_SIZE)
  if rules is None:
      fail(conn)

  conn.send(beta+rules)

  blob = conn.recv(32+RULE_SIZE+64)
  if len(blob)!=32+RULE_SIZE+64:
    fail(conn)

  pk = blob[0:32]
  try:
    blob = verify_blob(blob,pk)
  except ValueError:
    fail(conn)
  rules = blob[32:]

  save_blob(id,old,key)
  save_blob(id,'key',k)
  save_blob(id,'pub',pk)
  save_blob(id,'rules',rules)
  os.unlink(os.path.join(tdir,new))
  conn.send(b'ok')

def write(conn, msg):
  op,   msg = pop(msg,1)
  id,   msg = pop(msg,32)
  alpha,msg = pop(msg,32)
  id = binascii.hexlify(id).decode()
  # 1st find out if seed for this blob already exists (might be a normal sphinx pwd)
  tdir = os.path.join(datadir,id)
  if not os.path.exists(tdir):
    conn.send(b"new")
    # no seed available, need to set up that first.
    k=pysodium.randombytes(32)
    try:
        beta = sphinxlib.respond(alpha, k)
    except:
      fail(conn)
    conn.send(beta)

    # wait for auth signing pubkey and rules
    msg = conn.recv(8192+32+64+48) # pubkey, signature, max 8192B sealed(+48B) blob
    if len(msg)<=32+64+48:
      fail(conn)
    # verify auth sig on packet
    pk = msg[0:32]
    try:
      msg = verify_blob(msg,pk)
    except ValueError:
      fail(conn)

    blob = msg[32:]

    if not os.path.exists(datadir):
        os.mkdir(datadir,0o700)
    if not os.path.exists(tdir):
        os.mkdir(tdir,0o700)

    save_blob(id,'key',k)
    save_blob(id,'pub',pk)

    # 3rd phase
    update_blob(conn) # add user to host record
  else:
    conn.send(b"old")
    auth(conn, id, alpha)
    blob = conn.recv(8192+48) # max 8192B sealed(+48B) blob
    if len(blob)<=48:
      fail(conn)

  if not os.path.exists(datadir):
    os.mkdir(datadir,0o700)
  tdir = os.path.join(datadir,id)
  if not os.path.exists(tdir):
    os.mkdir(tdir,0o700)

  save_blob(id,'blob',blob)
  conn.send(b'ok')

def read(conn, msg):
  op,   msg = pop(msg,1)
  id,   msg = pop(msg,32)
  alpha,msg = pop(msg,32)
  id = binascii.hexlify(id).decode()
  auth(conn, id, alpha)

  blob = load_blob(id,'blob')
  if blob is None:
    blob = b''
  conn.send(blob)

def handler(conn):
   data = conn.recv(4096)
   if verbose:
     print('Data received:',data.hex())

   if data[0] == CREATE:
     create(conn, data)
   elif data[0] == GET:
     get(conn, data)
   elif data[0] == CHANGE:
     change(conn, data)
   elif data[0] == DELETE:
     delete(conn, data)
   elif data[0] == COMMIT:
     commit_undo(conn, data, 'new', 'old')
   elif data[0] == UNDO:
     commit_undo(conn, data, 'old', 'new')
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
        print('Bind failed. Error Code : %s Message: %s' % (str(msg[0]), msg[1]))
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
              except:
                print("fail")
                raise
              finally:
                try: conn.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                conn.close()
            else:
                kids.append(pid)

            try:
              pid, status = os.waitpid(0,os.WNOHANG)
              if(pid,status)!=(0,0):
                 kids.remove(pid)
            except ChildProcessError: pass

    except KeyboardInterrupt:
        pass
    s.close()

if __name__ == '__main__':
  main()
