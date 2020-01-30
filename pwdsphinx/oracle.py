#!/usr/bin/env python3

import socket, sys, os, datetime, binascii, pysodium, shutil, ssl
from SecureString import clearmem
from pwdsphinx import sphinxlib
from pwdsphinx.config import getcfg
cfg = getcfg('sphinx')

verbose = cfg['server'].getboolean('verbose')
address = cfg['server']['address']
port = int(cfg['server']['port'])
datadir = os.path.expanduser(cfg['server']['datadir'])
max_kids = int(cfg['server'].get('max_kids',5))
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

def fail(s):
    if verbose: print('fail')
    s.send(b'fail') # unauth'd plaintext :/ - only protected by tls
    s.shutdown(socket.SHUT_RDWR)
    s.close()

def _create(conn, msg):
    id = binascii.hexlify(msg[1:33]).decode()
    alpha = msg[33:65]

    sec, pub = sphinxlib.opaque_private_init_srv_respond(alpha)
    conn.send(pub)
    rec = conn.recv(4096)
    rec = sphinxlib.opaque_private_init_srv_finish(sec, pub, rec)

    # store record
    tdir = os.path.join(datadir,id)

    if os.path.exists(tdir):
      if verbose: print("%s exists" % tdir)
      fail(conn)
      return

    if not os.path.exists(datadir):
        os.mkdir(datadir,0o700)

    os.mkdir(tdir,0o700)

    with open(os.path.join(tdir,'rec'),'wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(rec)

    conn.send(b'ok')

def update_record(conn, msg = None, dst='rec'):
   if msg is None: msg = conn.recv(4096)
   id = binascii.hexlify(msg[1:33]).decode()
   # we return the record
   sk = get(conn,msg,True)
   if not sk: fail(conn)
   # we authenticate
   usr_auth = conn.recv(4096)
   auth = sphinxlib.opaque_f(sk, 2)
   if auth != usr_auth: fail(conn)

   alpha = conn.recv(4096)
   sec, pub = sphinxlib.opaque_private_init_srv_respond(alpha)
   conn.send(pub)

   rec = conn.recv(4096)
   rec = sphinxlib.opaque_private_init_srv_finish(sec, pub, rec)

   # store record
   tdir = os.path.join(datadir,id)

   if not os.path.exists(tdir):
     if verbose: print("%s does not exist" % tdir)
     fail(conn)
     return

   with open(os.path.join(tdir,dst),'wb') as fd:
     os.fchmod(fd.fileno(),0o600)
     fd.write(rec)

# msg format: 0x00|id[32]|alpha[32]
def create(conn, msg):
    _create(conn,msg)

    # handle upsert user
    # get id for user record
    msg = conn.recv(33)
    write(conn, msg)

# msg format: 0x66|id[32]|pub[xx] # fixme how big is pub?
def get(conn, msg, session=False):
    id = binascii.hexlify(msg[1:33]).decode()

    recfile = os.path.join(datadir,id, 'rec')

    if not os.path.exists(recfile):
        if verbose: print('%s does not exist' % recfile)
        fail(conn)
    with open(recfile,'rb') as fd:
        rec = fd.read()

    if len(rec) <= sphinxlib.OPAQUE_USER_RECORD_LEN:
        if verbose: print("rec wrong size")
        fail(conn)

    pub = msg[33:]
    resp, sk = sphinxlib.opaque_session_srv(pub, rec)
    conn.send(resp)

    if not session:
        clearmem(sk)
        conn.close()
    else:
        return sk

# msg format: 0xff|id[32]
def delete(conn, msg):
    id = binascii.hexlify(msg[1:33]).decode()
    sk = get(conn, msg, True)
    if not sk: fail(conn)
    usr_auth = conn.recv(4096)
    auth = sphinxlib.opaque_f(sk, 2)
    clearmem(sk)
    if auth != usr_auth:
        fail(conn)

    tdir = os.path.join(datadir,id)
    shutil.rmtree(tdir) # todo fixme use "secure delete"

    update_record(conn)

    conn.send(b'ok')

# msg format: 0x99|id[32]
def change(conn, msg):
    update_record(conn,msg, 'new')
    conn.send(b'ok')

# msg format: 0xff|id[32]
def commit_undo(conn, msg, src, dst):
    id = binascii.hexlify(msg[1:33]).decode()
    sk = get(conn, msg, True)
    if not sk: fail(conn)
    usr_auth = conn.recv(4096)
    auth = sphinxlib.opaque_f(sk, 2)
    clearmem(sk)
    if auth != usr_auth: fail(conn)

    tdir = os.path.join(datadir,id)
    try:
      with open(os.path.join(tdir,src),'rb') as fd:
        rec = fd.read()
    except FileNotFoundError:
      if verbose: print("not found %s/%s" % (tdir,src))
      fail(conn)
      return

    if(len(rec)<sphinxlib.OPAQUE_USER_RECORD_LEN):
      if verbose: print("invalid %s/%s" % (tdir,src))
      fail(conn)
      return

    os.rename(os.path.join(tdir,'rec'),os.path.join(tdir,dst))

    with open(os.path.join(tdir,'rec'),'wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(rec)

    os.unlink(os.path.join(tdir,src))

    conn.send(b'ok')
    conn.close()

def write(conn, msg):
   id = binascii.hexlify(msg[1:33]).decode()
   recfile = os.path.join(datadir,id, 'rec')
   if os.path.exists(recfile):
      # update the record file
      conn.send(b'\xff')
      update_record(conn)
   else:
      #create a new record
      conn.send(b'\x00')
      msg = conn.recv(4096)
      _create(conn, msg)

   conn.send(b"ok") # unfortunately we have no shared secret at this moment, so we need to send plaintext

def handler(conn):
   data = conn.recv(4096)

   if verbose:
     print('Data received: {}'.format(data.hex()))

   if data[0] == CREATE:
      create(conn, data)
   elif data[0] == GET:
      get(conn, data)
   elif data[0] == CHANGE:
      change(conn, data)
   elif data[0] == DELETE:
      delete(conn, data)
   elif data[0] == COMMIT:
      commit_undo(conn, data,'new','old')
   elif data[0] == UNDO:
      commit_undo(conn, data,'old','new')
   elif data[0] == READ:
      get(conn, data)
   elif data[0] == WRITE:
      write(conn, data)
   elif verbose:
      print("unknown op: 0x%02x" % data[0])

   #conn.shutdown(socket.SHUT_RDWR)
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
