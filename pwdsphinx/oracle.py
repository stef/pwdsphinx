#!/usr/bin/env python3

import socket, sys, os, datetime, binascii, pysodium, shutil
from SecureString import clearmem
from pwdsphinx import sphinxlib
from pwdsphinx.config import getcfg
cfg = getcfg('sphinx')

verbose = cfg['server'].getboolean('verbose')
address = cfg['server']['address']
port = int(cfg['server']['port'])
datadir = cfg['server']['datadir']
keydir = cfg['server']['keydir']

if(verbose):
  cfg.write(sys.stdout)

CREATE=0x00
GET=0x66
COMMIT=0x99
CHANGE=0xaa
DELETE=0xff

def fail(s):
    if verbose: print('fail')
    s.send(b'fail') # plaintext :/
    s.close()

def create(conn, msg):
    id = msg[1:33]
    alpha = msg[33:65]

    sec, pub = sphinxlib.opaque_private_init_srv_respond(alpha)
    conn.send(pub)
    rec = conn.recv(4096)
    rec = sphinxlib.opaque_private_init_srv_finish(sec, pub, rec)

    # store record
    tdir = os.path.expanduser(datadir+binascii.hexlify(id).decode())

    if os.path.exists(tdir):
      if verbose: print("%s exists" % tdir)
      fail(conn)
      return

    if not os.path.exists(os.path.expanduser(datadir)):
        os.mkdir(os.path.expanduser(datadir),0o700)

    os.mkdir(tdir,0o700)

    with open(tdir+'/rec','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(rec)

    conn.send(b"ok") # unfortunately we have no shared secret at this moment, so we need to send plaintext
    conn.close()

def get(conn, msg, session=False):
    id = msg[1:33]

    recfile = "%s/rec" % os.path.expanduser(datadir+binascii.hexlify(id).decode())

    if not os.path.exists(recfile):
        if verbose: print('%s does not exist' % recfile)
        fail(conn)
        return
    with open(recfile,'rb') as fd:
        rec = fd.read()

    if len(rec) <= sphinxlib.OPAQUE_USER_RECORD_LEN:
        if verbose: print("rec wrong size")
        fail(conn)
        return

    pub = msg[33:]
    resp, sk = sphinxlib.opaque_session_srv(pub, rec)
    conn.send(resp)

    if not session:
        clearmem(sk)
        conn.close()
    else:
        return sk

def delete(conn, msg):
    id = msg[1:33]
    sk = get(conn, msg, True)
    if not sk:
        return
    usr_auth = conn.recv(4096)
    auth = sphinxlib.opaque_f(sk, 2)
    if auth != usr_auth:
        fail(conn)
        return

    tdir = os.path.expanduser(datadir+binascii.hexlify(id).decode())
    shutil.rmtree(tdir)
    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    msg = pysodium.crypto_secretbox(b"ok",nonce,sk)
    conn.send(nonce+msg)
    conn.close()

def change(conn, msg):
    id = msg[1:33]
    sk = get(conn, msg, True)
    if not sk:
        return

    msg = conn.recv(4096)
    alpha = pysodium.crypto_secretbox_open(msg[pysodium.crypto_secretbox_NONCEBYTES:],msg[:pysodium.crypto_secretbox_NONCEBYTES],sk)
    sec, pub = sphinxlib.opaque_private_init_srv_respond(alpha)
    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    msg = pysodium.crypto_secretbox(pub,nonce,sk)
    conn.send(nonce+msg)

    msg = conn.recv(4096)
    try:
        rec = pysodium.crypto_secretbox_open(msg[pysodium.crypto_secretbox_NONCEBYTES:],msg[:pysodium.crypto_secretbox_NONCEBYTES],sk)
    except:
        fail(conn)
        return
    rec = sphinxlib.opaque_private_init_srv_finish(sec, pub, rec)

    # store record
    tdir = os.path.expanduser(datadir+binascii.hexlify(id).decode())

    if not os.path.exists(tdir):
      if verbose: print("%s does not exist" % tdir)
      fail(conn)
      return

    with open(tdir+'/new','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(rec)

    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    msg = pysodium.crypto_secretbox(b"ok",nonce,sk)
    conn.send(nonce+msg)
    conn.close()

def commit(conn, msg):
    id = msg[1:33]
    sk = get(conn, msg, True)
    if not sk:
        return
    usr_auth = conn.recv(4096)
    auth = sphinxlib.opaque_f(sk, 2)
    if auth != usr_auth:
        print("auth :/")
        fail(conn)
        return

    tdir = os.path.expanduser(datadir+binascii.hexlify(id).decode())
    try:
      with open(tdir+'/new','rb') as fd:
        rec = fd.read()
    except FileNotFoundError:
      if verbose: print("not found %s/new" % tdir)
      fail(conn)
      return

    if(len(rec)<sphinxlib.OPAQUE_USER_RECORD_LEN):
      if verbose: print("invalid %s/new" % tdir)
      fail(conn)
      return

    with open(tdir+'/rec','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(rec)

    os.unlink(tdir+'/new')

    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    msg = pysodium.crypto_secretbox(b"ok",nonce,sk)
    conn.send(nonce+msg)
    conn.close()

def handler(conn):
   data = conn.recv(4096)
   sk,pk=getkey(keydir)
   try:
     data = pysodium.crypto_box_seal_open(data,pk,sk)
   except:
     fail(conn)
     os._exit(0)
   clearmem(sk)

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
   os._exit(0)

def getkey(keydir):
  path = os.path.expanduser(keydir)
  try:
    with open(path+'server-key', 'rb') as fd:
      sk = fd.read(pysodium.crypto_box_SECRETKEYBYTES)
    with open(path+'server-key.pub', 'rb') as fd:
      pk = fd.read(pysodium.crypto_box_PUBLICKEYBYTES)
    return sk,pk
  except FileNotFoundError:
    print("no server key found, generating...")
    if not os.path.exists(path):
      os.mkdir(path,0o700)
    pk, sk = pysodium.crypto_box_keypair()
    with open(path+'server-key','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(sk)
    with open(path+'server-key.pub','wb') as fd:
      fd.write(pk)
    print("please share `%s` with all clients"  % (path+'server-key.pub'))
    return sk,pk

def main():
    sk,pk=getkey(keydir)
    clearmem(sk)

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
            while(len(kids)>5):
                pid, status = os.waitpid(0,0)
                kids.remove(pid)
            pid=os.fork()
            if pid==0:
                handler(conn)
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
