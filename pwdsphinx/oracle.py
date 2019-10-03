#!/usr/bin/env python3

import asyncio, datetime, os, binascii, shutil, sys
from SecureString import clearmem
import pysodium
from pwdsphinx import sphinxlib
from pwdsphinx.config import getcfg
cfg = getcfg('sphinx')

verbose = cfg['server'].getboolean('verbose')
address = cfg['server']['address']
port = cfg['server']['port']
datadir = cfg['server']['datadir']
keydir = cfg['server']['keydir']

if(verbose):
  cfg.write(sys.stdout)

CREATE=0x00
GET=0x66
COMMIT=0x99
CHANGE=0xaa
DELETE=0xff

def readf(fname):
  if not os.path.exists(fname):
    print(fname,'not exist')
    raise ValueError(b"fail")
  with open(fname,'rb') as fd:
    return fd.read()

def respond(chal, id, secret = None):
  path = os.path.expanduser(datadir+binascii.hexlify(id).decode())
  if not secret:
    try:
        secret = readf(path+'/key')
    except ValueError:
        return b'fail' # key not found

  if len(secret)!= sphinxlib.DECAF_255_SCALAR_BYTES:
    if verbose: print("secret wrong size")
    return b'fail'

  try:
    rule = readf(path+'/rule')
  except ValueError:
    return b'fail' # key not found

  with open(path+'/xpub','rb') as fd:
    xpk = fd.read()
  rule = pysodium.crypto_box_seal(rule, xpk)

  try:
    return sphinxlib.respond(chal, secret)+rule
  except ValueError:
    if verbose: print("respond fail")
    return b'fail'

class SphinxOracleProtocol(asyncio.Protocol):
  def connection_made(self, transport):
    if verbose:
      peername = transport.get_extra_info('peername')
      print('{} Connection from {}'.format(datetime.datetime.now(), peername))
    self.transport = transport

  def create(self, data):
    # needs pubkey, id, challenge, rule, sig(id)
    # returns output from ./response | fail
    pk = data[171:203]
    try:
      data = pysodium.crypto_sign_open(data, pk)
    except ValueError:
      print('invalid signature')
      return b'fail'
    id = data[1:33]
    chal = data[33:65]
    rule = data[65:107]
    tdir = os.path.expanduser(datadir+binascii.hexlify(id).decode())

    if os.path.exists(tdir):
      print(tdir, 'exists')
      return b'fail' # key already exists

    os.mkdir(tdir,0o700)

    with open(tdir+'/pub','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(pk)

    xpk = pysodium.crypto_sign_pk_to_box_pk(pk)
    with open(tdir+'/xpub','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(xpk)

    with open(tdir+'/rule','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(rule)

    k=pysodium.randombytes(32)
    with open(tdir+'/key','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(k)

    return respond(chal, id)

  def getpk(self,data):
    id = data[65:97]
    tdir = os.path.expanduser(datadir+binascii.hexlify(id).decode())
    with open(tdir+'/pub','rb') as fd:
      return fd.read()

  def get(self, data):
    # needs id, challenge, sig(id)
    # returns output from ./response | fail
    try:
      pk = self.getpk(data)
    except:
      return b'fail'
    try:
      data = pysodium.crypto_sign_open(data, pk)
    except ValueError:
      print('invalid signature')
      return b'fail'
    id = data[1:33]
    chal = data[33:65]

    return respond(chal, id)

  def change(self, data):
    # needs id, challenge, sig(id)
    # returns output from ./response | fail
    try:
      pk = self.getpk(data)
    except:
      return b'fail'
    try:
      data = pysodium.crypto_sign_open(data, pk)
    except ValueError:
      print('invalid signature')
      return b'fail'
    id = data[1:33]
    chal = data[33:65]

    tdir = os.path.expanduser(datadir+binascii.hexlify(id).decode())
    k=pysodium.randombytes(32)
    with open(tdir+'/new','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(k)

    try:
      rule = readf(tdir+"/rule")
    except:
      return b'fail'

    try:
      return respond(chal, id, secret = k)
    except ValueError:
      if verbose: print("respond fail")
      return b'fail'

  def commit(self, data):
    # needs id, sig(id)
    try:
      pk = self.getpk(data)
    except:
      return b'fail'
    try:
      data = pysodium.crypto_sign_open(data, pk)
    except ValueError:
      print('invalid signature')
      return b'fail'
    id = data[1:33]
    tdir = os.path.expanduser(datadir+binascii.hexlify(id).decode())

    try:
      with open(tdir+'/new','rb') as fd:
        k = fd.read()
    except FileNotFoundError:
      return b'fail'

    if(len(k)!=32):
      return b'fail'

    with open(tdir+'/key','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(k)

    os.unlink(tdir+'/new')

    return b'ok'

  def delete(self, data):
    # needs id, sig(id)
    # returns ok | fail
    try:
      pk = self.getpk(data)
    except:
      return b'fail'
    try:
      data = pysodium.crypto_sign_open(data, pk)
    except ValueError:
      print('invalid signature')
      return b'fail'
    id = data[1:33]

    tdir = os.path.expanduser(datadir+binascii.hexlify(id).decode())
    shutil.rmtree(tdir)
    return b'ok'

  def data_received(self, data):
    res = b''

    if verbose:
      print('Data received: {!r}'.format(data))

    esk,xsk,xpk = getkey(keydir)
    data = pysodium.crypto_box_seal_open(data,xpk,xsk)
    clearmem(xsk)

    if data[64] == 0:
      res = self.create(data)
    elif data[64] == GET:
      # needs id, challenge, sig(id)
      # returns output from ./response | fail
      res = self.get(data)
    elif data[64] == CHANGE:
      # needs id, challenge, sig(id)
      # changes stored secret
      # returns output from ./response | fail
      res = self.change(data)
    elif data[64] == DELETE:
      # needs id, sig(id)
      # returns ok|fail
      res = self.delete(data)
    elif data[64] == COMMIT:
      # needs id, sig(id)
      # returns ok|fail
      res = self.commit(data)

    if verbose:
      print('Send: {!r}'.format(res))

    res=pysodium.crypto_sign(res,esk)
    clearmem(esk)
    self.transport.write(res)

    if verbose:
      print('Close the client socket')
    self.transport.close()

def getkey(keydir):
  datadir = os.path.expanduser(keydir)
  try:
    with open(datadir+'server-key', 'rb') as fd:
      esk = fd.read(pysodium.crypto_sign_SECRETKEYBYTES)
    with open(datadir+'server-xkey', 'rb') as fd:
      xsk = fd.read(pysodium.crypto_box_SECRETKEYBYTES)
    with open(datadir+'server-xkey.pub', 'rb') as fd:
      xpk = fd.read(pysodium.crypto_box_PUBLICKEYBYTES)
    return esk, xsk, xpk
  except FileNotFoundError:
    print("no server key found, generating...")
    if not os.path.exists(datadir):
      os.mkdir(datadir,0o700)
    epk, esk = pysodium.crypto_sign_keypair()
    xsk = pysodium.crypto_sign_sk_to_box_sk(esk)
    xpk = pysodium.crypto_sign_pk_to_box_pk(epk)
    with open(datadir+'server-key','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(esk)
    with open(datadir+'server-key.pub','wb') as fd:
      fd.write(epk)
    with open(datadir+'server-xkey','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(xsk)
    with open(datadir+'server-xkey.pub','wb') as fd:
      fd.write(xpk)
    print("please share `%s` with all clients"  % (datadir+'server-key.pub'))
    return esk,xsk,xpk

def main():
  loop = asyncio.get_event_loop()
  # Each client connection will create a new protocol instance
  coro = loop.create_server(SphinxOracleProtocol, address, port)
  server = loop.run_until_complete(coro)

  esk,xsk,xpk = getkey(keydir)
  if None in (esk,xsk,xpk):
    print("no server keys available.\nabort")
    sys.exit(1)
  clearmem(xsk)
  clearmem(esk)

  # Serve requests until Ctrl+C is pressed
  if verbose:
    print('Serving on {}'.format(server.sockets[0].getsockname()))
  try:
    loop.run_forever()
  except KeyboardInterrupt:
    pass

  # Close the server
  server.close()
  loop.run_until_complete(server.wait_closed())
  loop.close()

if __name__ == '__main__':
  main()
