#!/usr/bin/env python3

import sys, os, asyncio, io, struct, binascii, platform
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
port = cfg['client']['port']
datadir = cfg['client']['datadir']

CREATE=b'\x00'
GET=b'\x66'
COMMIT=b'\x99'
CHANGE=b'\xaa'
DELETE=b'\xff'

class SphinxClientProtocol(asyncio.Protocol):
  def __init__(self, message, loop,b,pwd,handler,cb):
    self.b = b
    self.pwd=pwd
    self.message = message
    self.loop = loop
    self.handler = handler
    self.cb = cb

  def connection_made(self, transport):
    transport.write(self.message)
    if verbose: print('Data sent: {!r}'.format(self.message), file=sys.stderr)

  def data_received(self, data):
    if verbose: print('Data received: ', data, file=sys.stderr)

    try:
      data = pysodium.crypto_sign_open(data, self.handler.getserverkey())
    except ValueError:
      raise ValueError('invalid signature.\nabort')

    if data!=b'ok' and (data[:-42] == b'fail' or len(data)!=sphinxlib.DECAF_255_SER_BYTES+42):
        raise ValueError('fail')

    if not self.b:
      self.cb()
      return

    rwd=sphinxlib.finish(self.pwd, self.b, data[:sphinxlib.DECAF_255_SER_BYTES])

    if self.handler.namesite is not None:
      if self.handler.namesite['name'].encode() not in self.handler.list(self.handler.namesite['site']):
        self.handler.cacheuser(self.handler.namesite)

    rule = data[sphinxlib.DECAF_255_SER_BYTES:]
    if len(rule)!=42:
      raise ValueError('fail')
    rk = pysodium.crypto_generichash(self.handler.getkey(),self.handler.getsalt())
    rule = pysodium.crypto_secretbox_open(rule[24:], rule[:24],rk)
    rule = struct.unpack(">H",rule)[0]
    size = (rule & 0x7f)
    rule = {c for i,c in enumerate(('u','l','s','d')) if (rule >> 7) & (1 << i)}
    self.cb(bin2pass.derive(rwd,rule,size).decode())

  def connection_lost(self, exc):
    if verbose:
        print('The server closed the connection', file=sys.stderr)
        print('Stop the event loop', file=sys.stderr)
    self.loop.stop()

class SphinxHandler():
  def __init__(self, datadir):
    self.datadir=datadir
    self.namesite = None

  def getkey(self):
    datadir = os.path.expanduser(self.datadir)
    try:
      fd = open(datadir+'key', 'rb')
      key = fd.read()
      fd.close()
      return key
    except FileNotFoundError:
      if not os.path.exists(datadir):
        os.mkdir(datadir,0o700)
      pk, sk = pysodium.crypto_sign_keypair()
      with open(datadir+'key','wb') as fd:
        if not win: os.fchmod(fd.fileno(),0o600)
        fd.write(sk)
      return sk

  def getsalt(self):
    datadir = os.path.expanduser(self.datadir)
    try:
      fd = open(datadir+'salt', 'rb')
      salt = fd.read()
      fd.close()
      return salt
    except FileNotFoundError:
      if not os.path.exists(datadir):
        os.mkdir(datadir,0o700)
      salt = pysodium.randombytes(32)
      with open(datadir+'salt','wb') as fd:
        if not win: os.fchmod(fd.fileno(),0o600)
        fd.write(salt)
      return salt

  def getusers(self, id):
    datadir = os.path.expanduser(self.datadir)
    try:
      with open(datadir+binascii.hexlify(id).decode(), 'rb') as fd:
        return [x.strip() for x in fd.readlines()]
    except FileNotFoundError:
        return None

  def deluser(self, id, user):
    userfile = os.path.expanduser(self.datadir+binascii.hexlify(id).decode())
    try:
      with open(userfile, 'rb') as fd:
        users=[x.strip() for x in fd.readlines() if x.strip() != user.encode()]
      if users != []:
        with open(userfile, 'wb') as fd:
            # skip rules
            fd.write(b'\n'.join(users))
      else:
        os.unlink(userfile)
    except FileNotFoundError:
      return None

  def cacheuser(self, namesite):
    site=namesite['site']
    user=namesite['name']
    salt = self.getsalt()
    hostid = pysodium.crypto_generichash(site, salt, 32)
    userfile = os.path.expanduser(self.datadir+binascii.hexlify(hostid).decode())
    try:
      if not os.path.exists(userfile):
        with open(userfile, 'wb') as fd:
            fd.write(user.encode())
      else:
        with open(userfile, 'ab') as fd:
            fd.write(b"\n"+user.encode())
    except:
      pass

  def getserverkey(self):
    datadir = os.path.expanduser(self.datadir)
    try:
      with open(datadir+'server-key.pub', 'rb') as fd:
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

  def getid(self, host, user):
    salt = self.getsalt()
    return pysodium.crypto_generichash(b''.join((user.encode(),host.encode())), salt, 32)

  def doSphinx(self, message, host, b, pwd, cb):
    signed=pysodium.crypto_sign(message,self.getkey())
    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: SphinxClientProtocol(signed, loop, b, pwd, self, cb), address, port)
    try:
      loop.run_until_complete(coro)
      loop.run_forever()
    except:
      raise

  def create(self, cb, pwd, user, host, char_classes, size=0):
    if set(char_classes) - {'u','l','s','d'}:
      raise ValueError("error: rules can only contain ulsd.")
    try: size=int(size)
    except:
      raise ValueError("error: size has to be integer.")
    self.namesite={'name': user, 'site': host}

    rules = sum(1<<i for i, c in enumerate(('u','l','s','d')) if c in char_classes)
    # pack rule
    rule=struct.pack('>H', (rules << 7) | (size & 0x7f))
    # encrypt rule
    sk = self.getkey()
    rk = pysodium.crypto_generichash(sk,self.getsalt())
    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    rule = nonce+pysodium.crypto_secretbox(rule,nonce,rk)

    b, c = sphinxlib.challenge(pwd)
    message = b''.join([CREATE,
                        self.getid(host, user),
                        c,
                        rule,
                        pysodium.crypto_sign_sk_to_pk(sk)])
    self.doSphinx(message, host, b, pwd, cb)

  def get(self, cb, pwd, user, host):
    b, c = sphinxlib.challenge(pwd)
    self.namesite={'name': user, 'site': host}
    message = b''.join([GET,
                        self.getid(host, user),
                        c])
    self.doSphinx(message, host, b, pwd, cb)

  def change(self, cb, pwd, user, host):
    b, c = sphinxlib.challenge(pwd)
    self.namesite={'name': user, 'site': host}
    message = b''.join([CHANGE,
                        self.getid(host, user),
                        c])
    self.doSphinx(message, host, b, pwd, cb)

  def commit(self, cb, user, host):
    message = b''.join([COMMIT,self.getid(host, user)])
    self.namesite={'name': user, 'site': host}
    def callback():
      return
    self.doSphinx(message, host, None, None, callback)

  def delete(self, user, host):
    message = b''.join([DELETE,self.getid(host, user)])
    salt = self.getsalt()
    hostid = pysodium.crypto_generichash(host, salt, 32)
    def callback():
      self.deluser(hostid,user)
    self.doSphinx(message, host, None, None, callback)

  def list(self, host):
    salt = self.getsalt()
    hostid = pysodium.crypto_generichash(host, salt, 32)
    return self.getusers(hostid) or []

def main():
  def usage():
    print("usage: %s create <user> <site> [u][l][d][s] [<size>]" % sys.argv[0])
    print("usage: %s <get|change|commit|delete> <user> <site>" % sys.argv[0])
    print("usage: %s list <site>" % sys.argv[0])
    sys.exit(1)

  if len(sys.argv) < 2: usage()

  handler = SphinxHandler(datadir)

  if sys.argv[1] == 'create':
    if len(sys.argv) not in (5,6): usage()
    pwd = sys.stdin.buffer.read()
    if len(sys.argv) == 6:
      size=sys.argv[5]
    else:
      size = 0
    handler.create(print, pwd, sys.argv[2], sys.argv[3], sys.argv[4], size)
  elif sys.argv[1] == 'get':
    if len(sys.argv) != 4: usage()
    # needs id, challenge, sig(id)
    pwd = sys.stdin.buffer.read()
    handler.get(print, pwd, sys.argv[2], sys.argv[3])
  elif sys.argv[1] == 'change':
    if len(sys.argv) != 4: usage()
    # needs id, challenge, sig(id)
    pwd = sys.stdin.buffer.read()
    handler.change(print, pwd, sys.argv[2], sys.argv[3])
  elif sys.argv[1] == 'commit':
    if len(sys.argv) != 4: usage()
    handler.commit(print, sys.argv[2], sys.argv[3])
  elif sys.argv[1] == 'delete':
    if len(sys.argv) != 4: usage()
    handler.delete(sys.argv[2], sys.argv[3])
  elif sys.argv[1] == 'list':
    if len(sys.argv) != 3: usage()
    print(b'\n'.join(handler.list(sys.argv[2])).decode())
  else:
    usage()

if __name__ == '__main__':
  main()
