#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2018-2024, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import socket, sys, ssl, os, datetime, binascii, shutil, os.path, traceback, struct, select
from os import access, R_OK
from os.path import isfile, getsize
import pysodium
import equihash
import pyoprf
from pwdsphinx.config import getcfg
from pwdsphinx.consts import *
cfg = getcfg('sphinx')

# todo genkey ltsig integrate into oracle

verbose = cfg['server'].get('verbose', False)
address = cfg['server'].get('address', '127.0.0.1')
port = int(cfg['server'].get('port',2355))
timeout = int(cfg['server'].get('timeout',"3"))
max_kids = int(cfg['server'].get('max_kids',5))
datadir = os.path.expanduser(cfg['server'].get('datadir',"/var/lib/sphinx"))
ts_epsilon = 1200 # todo make configurable
try:
    ssl_key = os.path.expanduser(cfg['server']['ssl_key'])
except KeyError:
    print("Error: ssl_key missing! must specify it in the config file")

try:
    ssl_cert = os.path.expanduser(cfg['server']['ssl_cert'])
except KeyError:
    print("Error: ssl_cert missing! must specify it in the config file")
try:
    ltsigkey_path = os.path.expanduser(cfg['server']['ltsigkey'])
except KeyError:
    print("Error: ltsigkey missing! must specify it in the config file")

rl_decay = int(cfg['server'].get('rl_decay',1800))
rl_threshold = int(cfg['server'].get('rl_threshold',1))
rl_gracetime = int(cfg['server'].get('rl_gracetime',10))

if(verbose):
  print(f"pid:          {os.getpid()}")
  print(f"address:      {address}:{port}")
  print(f"timeout:      {timeout}s")
  print(f"max kids:     {max_kids}")
  print(f"datadir:      {datadir}")
  print(f"ssl_key:      {ssl_key}")
  if 'ssl_cert' in globals():
      print(f"ssl_cert:     {ssl_cert}")
  print(f"rl decay:     {rl_decay}s")
  print(f"rl threshold: {rl_threshold}")
  print(f"rl gracetime: {rl_gracetime}s")

Difficulties = [
    # timeouts are based on benchmarking a raspberry pi 1b
    { 'n': 60,  'k': 4, 'timeout': 1 },    # 320KiB, ~0.02
    { 'n': 65,  'k': 4, 'timeout': 2 },    # 640KiB, ~0.04
    { 'n': 70,  'k': 4, 'timeout': 4 },    # 1MiB, ~0.08
    { 'n': 75,  'k': 4, 'timeout': 9 },    # 2MiB, ~0.2
    { 'n': 80,  'k': 4, 'timeout': 16 },   # 5MiB, ~0.5
    { 'n': 85,  'k': 4, 'timeout': 32 },   # 10MiB, ~0.9
    { 'n': 90,  'k': 4, 'timeout': 80 },   # 20MiB, ~2.4
    { 'n': 95,  'k': 4, 'timeout': 160 },  # 40MiB, ~4.6
    # timeouts below are interpolated from above
    { 'n': 100, 'k': 4, 'timeout': 320 },  # 80MiB, ~7.8
    { 'n': 105, 'k': 4, 'timeout': 640 },  # 160MiB, ~25
    { 'n': 110, 'k': 4, 'timeout': 1280 }, # 320MiB, ~57
    { 'n': 115, 'k': 4, 'timeout': 2560 }, # 640MiB, ~70
    { 'n': 120, 'k': 4, 'timeout': 5120 }, # 1GiB, ~109
]
RL_Timeouts = {(e['n'],e['k']): e['timeout'] for e in Difficulties}

normal = "\033[38;5;%sm"
reset = "\033[0m"

def fail(s):
    if verbose:
        traceback.print_stack()
        print('fail')
    s.send(b'\x00\x04fail') # plaintext :/ todo use ltsigkey?
    s.shutdown(socket.SHUT_RDWR)
    s.close()
    os._exit(0)

def pop(obj, cnt, astype=None):
  if astype is not None:
      return astype(obj[:cnt]), obj[cnt:]
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

def read_pkt(s,size):
    res = []
    read = 0
    while read<size:
      res.append(s.recv(size-read))
      read+=len(res[-1])
      if len(res[-1]) == 0: raise ValueError("end of stream?")
    return b''.join(res)

def update_blob(s):
    signed_id = s.recv(32+64)
    if len(signed_id)!=32+64:
      fail(s)
    if sum(signed_id[:32]) == 0: return

    id = binascii.hexlify(signed_id[:32]).decode()
    pk = load_blob(id,'pub')
    if pk is None:
      if os.path.exists(os.path.join(datadir,id)):
        print("user blob authkey not found, but dir exists:", id)
        fail(s)
      new = True
      blob = b'\x00\x00'
    else:
      try:
        blob = verify_blob(signed_id,pk)
      except ValueError:
        print('invalid signature on user blob id')
        fail(s)
      blob = load_blob(id,'blob')
      if blob is None:
        print("user blob authkey fund, but no blob for id:", id)
        fail(s)
      new = False
    s.sendall(blob)
    if new:
      pk = s.recv(32)
      prefix = s.recv(2)
      bsize = struct.unpack('!H', prefix)[0]
      signedblob = read_pkt(s, bsize+64)
      blob = pk+prefix+signedblob
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
      prefix = s.recv(2)
      bsize = struct.unpack('!H', prefix)[0]
      signedblob = read_pkt(s, bsize+64)
      blob = prefix+signedblob
      pk = load_blob(id,'pub')
      try:
        blob = verify_blob(blob,pk)
      except ValueError:
        print('invalid signature on msg')
        fail(s)
      if bsize == 41: # version + nonce + mac
        tdir = os.path.join(datadir,id)
        shutil.rmtree(tdir)
        return
    save_blob(id,'blob',blob)

# msg format: 0x00|id[32]|alpha[32]
def create(s, msg):
    if len(msg)!=65:
      fail(s)
    if verbose: print('Data received:',msg.hex())
    op,   msg = pop(msg,1)
    id,   msg = pop(msg,32)
    alpha,msg = pop(msg,32)

    # check if id is unique
    id = binascii.hexlify(id).decode()
    tdir = os.path.join(datadir,id)
    if(os.path.exists(tdir)):
      fail(s)

    # 1st step OPRF with a new seed
    k=b'\x01'+pysodium.randombytes(32)
    try:
      beta = k[:1]+pyoprf.evaluate(k[1:], alpha)
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

    # 3rd phase
    update_blob(s) # add user to host record

    if not os.path.exists(datadir):
        os.mkdir(datadir,0o700)
    os.mkdir(tdir,0o700)

    save_blob(id,'key',k)
    save_blob(id,'pub',pk)
    save_blob(id,'rules',rules)

    s.send(b'ok')

def dkg(s, msg0, aux):
    with open(ltsigkey_path, 'rb') as fd:
      ltsigkey = fd.read()
    if len(ltsigkey) != pysodium.crypto_sign_SECRETKEYBYTES:
      print("Invalid long-term signature key")
      fail(s)

    peer = pyoprf.tpdkg_peer_start(ts_epsilon, ltsigkey, msg0)

    while pyoprf.tpdkg_peer_not_done(peer):
      in_size = pyoprf.tpdkg_peer_input_size(peer)
      if in_size > 0:
        msg = read_pkt(s, in_size)
      else:
        msg = b''

      cur_step = pyoprf.tpdkg_peerstate_step(peer)
      try:
        out = pyoprf.tpdkg_peer_next(peer, msg)
      except Exception as e:
        print(f"{e} | peer step {cur_step}")
        fail(s)
      if(len(out)>0):
        s.send(out)

    share = pyoprf.tpdkg_peerstate_share(peer)

    return share

# msg format: 0xf0|msg0[pyoprf.tpdkg_msg0_SIZE]|id[32]|alpha[32]]
def create_dkg(s, msg):
    if len(msg)!=65+pyoprf.tpdkg_msg0_SIZE:
      print(f"{len(msg)} != {pyoprf.tpdkg_msg0_SIZE}",file=sys.stderr)
      fail(s)
    if verbose: print('Data received:',msg.hex())
    op,    msg = pop(msg,1)
    id,    msg = pop(msg,32)
    alpha, msg0 = pop(msg,32)

    if len(msg0) != pyoprf.tpdkg_msg0_SIZE:
      print(f"msg0 is invalid size {len(msg0)}")
      fail(s)

    aux = b'%s%s' % (op, alpha) # for the transcript

    # check if id is unique
    id = binascii.hexlify(id).decode()
    tdir = os.path.join(datadir,id)
    if(os.path.exists(tdir)):
      fail(s)

    xi = dkg(s, msg0, aux)

    #k=pysodium.randombytes(32)
    try:
      beta = pyoprf.evaluate(xi[1:], alpha)
    except:
      fail(s)

    msg = bytes([xi[0]])+beta
    s.send(msg)

    # wait for auth signing pubkey and rules
    msg = s.recv(32+RULE_SIZE+64) # pubkey, rule, signature
    if len(msg)!=32+RULE_SIZE+64:
      fail(s)
    # verify auth sig on packet
    pk = msg[:32]
    try:
      msg = verify_blob(msg,pk)
    except ValueError:
      fail(s)

    rules = msg[32:]

    # 3rd phase
    update_blob(s) # add user to host record

    if not os.path.exists(datadir):
        os.mkdir(datadir,0o700)
    os.mkdir(tdir,0o700)

    save_blob(id,'key',xi)
    save_blob(id,'pub',pk)
    save_blob(id,'rules',rules)

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
    k = load_blob(id,'key',33)
    if k is None:
      # maybe execute protocol with static but random value to not leak which host ids exist?
      fail(conn)

    rules = load_blob(id,'rules', RULE_SIZE)
    if rules is None:
        fail(conn)

    try:
        beta = pyoprf.evaluate(k[1:], alpha)
    except:
      fail(conn)

    conn.send(k[:1]+beta+rules)

# msg format: 0x69|id[32]|alpha[32]
def v1get(conn, msg):
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

    rules = load_blob(id,'rules', V1RULE_SIZE)
    if rules is None:
        fail(conn)

    try:
        if not pysodium.crypto_core_ristretto255_is_valid_point(alpha):
            raise ValueError("invalid alpha")
        beta = pysodium.crypto_scalarmult_ristretto255(k, alpha)
    except:
      fail(conn)

    conn.send(beta+rules)

def auth(s,id,alpha, isv1=False):
  pk = load_blob(id,'pub',32)
  if pk is None:
    print('no pubkey found in %s' % id)
    fail(s)
  nonce=pysodium.randombytes(32)
  k = load_blob(id,'key',33 if not isv1 else 32)
  if k is not None:
    try:
       if not isv1:
           beta = bytes([k[0]])+pyoprf.evaluate(k[1:], alpha)
       else:
           if not pysodium.crypto_core_ristretto255_is_valid_point(alpha):
               raise ValueError("invalid alpha")
           beta = pysodium.crypto_scalarmult_ristretto255(k, alpha)
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
  else:
    s.send(b'\x00\x04auth') # plaintext :/ todo use ltsigkey?

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

  alpha = conn.recv(32)
  if(len(alpha)!=32):
    fail(conn)

  k=b'\x01'+pysodium.randombytes(32)

  try:
      beta = k[:1]+pyoprf.evaluate(k[1:], alpha)
  except:
    fail(conn)

  conn.send(beta)

  blob = conn.recv(32+RULE_SIZE+64)
  if len(blob)!=32+RULE_SIZE+64:
    fail(conn)

  pk = blob[:32]
  try:
    rules = verify_blob(blob,pk)[32:]
  except ValueError:
    fail(conn)

  save_blob(id,'new',k)
  save_blob(id,"rules.new", rules)
  save_blob(id,"pub.new", pk)
  conn.send(b'ok')

def change_dkg(s, msg):
  op,   msg = pop(msg,1)
  id,   msg = pop(msg,32)
  alpha,msg = pop(msg,32)
  if msg!=b'':
    if verbose: print('invalid get msg, trailing content %r' % msg)
    fail(s)

  aux = b'%s%s' % (op, alpha)

  id = binascii.hexlify(id).decode()
  tdir = os.path.join(datadir,id)
  if not os.path.exists(tdir):
    if verbose: print("%s doesn't exist" % tdir)
    fail(s)

  auth(s, id, alpha)

  msg = s.recv(pyoprf.tpdkg_msg0_SIZE+32)
  alpha,msg0 = pop(msg,32)
  if len(msg0) != pyoprf.tpdkg_msg0_SIZE:
    print(f"msg0 is invalid size {len(msg0)}")
    fail(s)

  xi = dkg(s, msg0, aux)

  try:
    beta = pyoprf.evaluate(xi[1:], alpha)
  except:
    fail(s)

  s.send(bytes([xi[0]])+beta)

  blob = s.recv(32+RULE_SIZE+64)
  if len(blob)!=32+RULE_SIZE+64:
    fail(s)

  pk = blob[:32]
  try:
    rules = verify_blob(blob,pk)[32:]
  except ValueError:
    fail(s)

  save_blob(id,'new',xi)
  save_blob(id,"rules.new", rules)
  save_blob(id,"pub.new", pk)
  s.send(b'ok')

def delete(conn, msg, isv1=False):
  op,   msg = pop(msg,1)
  id,   msg = pop(msg,32)
  alpha,msg = pop(msg,32)
  if msg!=b'':
    if verbose: print('invalid get msg, trailing content %r' % msg)
    fail(conn)

  id = binascii.hexlify(id).decode()
  auth(conn, id, alpha, isv1)

  tdir = os.path.join(datadir,id)
  if not os.path.exists(tdir):
    if verbose: print("%s doesn't exist" % tdir)
    fail(conn)

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

  if (new_rules:=load_blob(id,'rules.%s' % new, RULE_SIZE)) is None:
    fail(conn)
  if (cur_rules:=load_blob(id,'rules', RULE_SIZE)) is None:
    fail(conn)
  if (new_pub:=load_blob(id,'pub.%s' % new, 32)) is None:
    fail(conn)
  if (cur_pub:=load_blob(id,'pub', 32) )is None:
    fail(conn)
  if (new_key:= load_blob(id, new, 33)) is None:
    fail(conn)
  if (cur_key:= load_blob(id, 'key', 33)) is None:
    fail(conn)

  save_blob(id,old,cur_key)
  #clearmem(cur_key)
  save_blob(id,"rules.%s" % old, cur_rules)
  save_blob(id,"pub.%s" % old, cur_pub)

  save_blob(id,"key",new_key)
  #clearmem(new_key)
  save_blob(id,"rules", new_rules)
  save_blob(id,"pub", new_pub)

  os.unlink(os.path.join(tdir,new))
  os.unlink(os.path.join(tdir,"pub.%s" % new))
  os.unlink(os.path.join(tdir,"rules.%s" % new))

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

def handler(conn, data):
   if verbose:
     print('Data received:',data.hex())

   if data[0:1] == GET:
     get(conn, data)
   elif data[0:1] == V1GET:
     v1get(conn, data)
   elif data[0:1] == CHANGE:
     change(conn, data)
   elif data[0:1] == CHANGE_DKG:
     change_dkg(conn, data)
   elif data[0:1] == DELETE:
     delete(conn, data)
   elif data[0:1] == V1DELETE:
     delete(conn, data, True)
   elif data[0:1] == COMMIT:
     commit_undo(conn, data, 'new', 'old')
   elif data[0:1] == UNDO:
     commit_undo(conn, data, 'old', 'new')
   elif data[0:1] == READ:
     read(conn, data)
   elif verbose:
     print("unknown op: 0x%02x" % data[0])

   conn.close()
   os._exit(0)

def create_challenge(conn):
  req = conn.read(65)
  if req[0:1] == READ:
    if len(req)!=33:
      fail(conn)
  elif len(req)!=65:
    fail(conn)
  now = datetime.datetime.now().timestamp()
  id = binascii.hexlify(req[1:33]).decode()
  diff = load_blob(id,'difficulty',9) # ts: u32, level: u8, count:u32
  if not diff: # no diff yet, use easiest hardness
    n = Difficulties[0]['n']
    k = Difficulties[0]['k']
    level = 0
    count = 0
  else:
    level = struct.unpack("B", diff[0:1])[0]
    count = struct.unpack("I", diff[1:5])[0]
    ts = struct.unpack("I", diff[5:])[0]
    if level >= len(Difficulties):
      print("invalid level in rl_ctx:", level)
      level = len(Difficulties) - 1
      count = 0
    elif ((now - rl_decay) > ts and level > 0): # cooldown, decay difficulty
      periods = int((now - ts) // rl_decay)
      if level >= periods:
        level -= periods
      else:
        level = 0
      count = 0
    else: # increase hardness
      if count >= rl_threshold and (level < len(Difficulties) - 1):
        count = 0
        level+=1
      else:
        count+=1
    n = Difficulties[level]['n']
    k = Difficulties[level]['k']

  if (level == len(Difficulties) - 1) and count>rl_threshold*2:
    print(f"{normal}alert{normal}: someones trying (%d) really hard at: %s" %
          (196, 253, count, id))

  rl_ctx = b''.join([
    struct.pack("B", level),   # level
    struct.pack("I", count),   # count
    struct.pack('I', int(now)) # ts
  ])
  if(verbose): print("rl difficulty", {"level": level, "count": count, "ts": int(now)})
  try:
    save_blob(id, 'difficulty', rl_ctx)
  except FileNotFoundError:
    if diff: raise

  challenge = b''.join([bytes([n, k]), struct.pack('Q', int(now))])

  key = load_blob('', "key", 32)
  if not key:
    key=pysodium.randombytes(32)
    save_blob('','key',key)

  state = pysodium.crypto_generichash_init(32, key)
  pysodium.crypto_generichash_update(state,req)
  pysodium.crypto_generichash_update(state,challenge)
  sig = pysodium.crypto_generichash_final(state,32)

  resp = b''.join([challenge, sig])
  conn.send(resp)

def verify_challenge(conn):
  # read challenge
  challenge = conn.read(1+1+8+32) # n,k,ts,sig
  if(len(challenge)!=42):
    fail(conn)
  n, tmp = pop(challenge,1)
  n = n[0]
  k, tmp = pop(tmp,1)
  k = k[0]
  ts, tmp = pop(tmp,8)
  ts = struct.unpack("Q", ts)[0]
  sig, tmp = pop(tmp,32)

  # read request
  req_type = conn.read(1)
  if req_type[0:1] == READ:
    payload = conn.read(32)
    if len(payload)!=32: fail(conn)
  else:
    payload = conn.read(64)
    if len(payload)!=64: fail(conn)
  req = req_type + payload
  # read mac key
  key = load_blob('', "key", 32)
  if not key:
    fail(conn)

  tosign = challenge[:10]

  state = pysodium.crypto_generichash_init(32, key)
  pysodium.crypto_generichash_update(state,req)
  pysodium.crypto_generichash_update(state,tosign)
  mac = pysodium.crypto_generichash_final(state,32)
  # poor mans const time comparison
  if(sum(m^i for (m, i) in zip(mac,sig))):
    fail(conn)

  now = datetime.datetime.now().timestamp()
  if now - (RL_Timeouts[(n,k)]+rl_gracetime) > ts:
    # solution is too old
    fail(conn)

  solsize = equihash.solsize(n,k)
  solution = conn.read(solsize)
  if len(solution)!= solsize:
    fail(conn)

  seed = b''.join([challenge,req])
  if not equihash.verify(n,k, seed, solution):
    fail(conn)

  handler(conn, req)

def ratelimit(conn):
   op = conn.recv(1)
   if op == CREATE:
     data = CREATE+conn.recv(64)
     create(conn, data)
   elif op == CREATE_DKG:
     data = CREATE_DKG+conn.recv(65+pyoprf.tpdkg_msg0_SIZE)
     create_dkg(conn, data)
   elif op == CHALLENGE_CREATE:
     create_challenge(conn)
   elif op == CHALLENGE_VERIFY:
     verify_challenge(conn)

def main(debug=False):
    if debug == True:
        import ctypes
        libc = ctypes.cdll.LoadLibrary('libc.so.6')
        fdopen = libc.fdopen
        log_file = ctypes.c_void_p.in_dll(pyoprf.liboprf,'log_file')
        fdopen.restype = ctypes.c_void_p
        log_file.value = fdopen(2, 'w')

    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=ssl_cert, keyfile=ssl_key)

    socket.setdefaulttimeout(timeout)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((address, port))
    except socket.error as msg:
        print(f'Bind to {address}:{port} failed. Error {msg}')
        sys.exit()
    #Start listening on socket
    s.listen()
    kids = []
    try:
        # main loop
        while 1:
            #wait to accept a connection - blocking call
            r,w,x = select.select([s], [], [], 0.5)
            if len(r) == 1:
              conn, addr = s.accept()
            else:
              try:
                pid, status = os.waitpid(-1, os.WNOHANG)
                if pid != 0:
                  print("remove pid", pid)
                  kids.remove(pid)
                continue
              except ChildProcessError:
                continue

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
                ratelimit(conn)
              except:
                print("fail")
                raise
              finally:
                try: conn.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                conn.close()
              sys.exit(0)
            else:
                kids.append(pid)

            try:
              pid, status = os.waitpid(-1,os.WNOHANG)
              if pid!=0:
                 kids.remove(pid)
            except ChildProcessError: pass

    except KeyboardInterrupt:
        pass
    s.close()

def is_readable(path):
  return isfile(path) and access(path, R_OK)

def missing_file(path):
    print(f"The SSL key at {path} is not a readable file. Make sure this is a proper ssl key.")
    print(f"Our GettingStarted document gives simple example of how to do so.")
    print(f"Check out https://sphinx.pm/server_install.html .")
    print(f"Aborting.")
    exit(1)

def parse_params():
  if not is_readable(ssl_key):
    missing_file(ssl_key)
  if not is_readable(ssl_cert):
    missing_file(ssl_cert)
  if not is_readable(ltsigkey_path) and 'init' not in sys.argv:
    print(f"Long-term signing key at {ltsigkey_path} is not readable.")
    print(f"You can generate one by running: {sys.argv[0]} init")
  if not getsize != pysodium.crypto_sign_SECRETKEYBYTES:
    print(f"The long-term signing key of the oracle has an invalid size, maybe it's corrupt?")
    print("abort.")
    exit(1)

  debug=False
  if 'debug' in sys.argv:
    debug = True
  if not 'init' in sys.argv:
    main(debug)
  else:
    # init
    pk, sk = pysodium.crypto_sign_keypair()
    with open(ltsigkey_path, 'xb') as fd:
      fd.write(sk)

    with open(f"{ltsigkey_path}.pub", 'xb') as fd:
      fd.write(pk)

    print(f"successfully created long-term signature key pair at:")
    print(f"{ltsigkey_path}")
    print(f"and the public key - which you should make available to all clients -, is at:")
    print(f"{ltsigkey_path}.pub")
    print(f"The following is the base64 encoded public key that you can also share:")
    print(f"{binascii.b2a_base64(pk).strip().decode('utf8')}")

if __name__ == '__main__':
  parse_params()
