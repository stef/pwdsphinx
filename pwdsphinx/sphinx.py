#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2018-2024, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import sys, os, socket, ssl, struct, platform, getpass, binascii, zlib
import concurrent.futures
from SecureString import clearmem
import pysodium, pyoprf
from qrcodegen import QrCode
try:
    from zxcvbn import zxcvbn
except ImportError:
    zxcvbn = None
from equihash import solve
from itertools import permutations
from pyoprf.multiplexer import Multiplexer

try:
  from pwdsphinx import bin2pass, v1sphinx
  from pwdsphinx.config import getcfg
  from pwdsphinx.consts import *
  from pwdsphinx.utils import split_by_n
  from pwdsphinx.ext import init_browser_ext
  from pwdsphinx.converter import convert
  from pwdsphinx import ostore
except ImportError:
  import bin2pass, ostore, v1sphinx
  from config import getcfg
  from consts import *
  from utils import split_by_n
  from ext import init_browser_ext
  from converter import convert

win=False
if platform.system() == 'Windows':
  win=True

#### config ####

cfg = getcfg('sphinx')

verbose = cfg['client'].get('verbose', False)
hostname = cfg['client'].get('address','127.0.0.1')
address = socket.gethostbyname(hostname)
port = int(cfg['client'].get('port',2355))
datadir = os.path.expanduser(cfg['client'].get('datadir','~/.config/sphinx'))
try:
  ssl_cert = os.path.expanduser(cfg['client'].get('ssl_cert')) # only for dev, production system should use proper certs!
except TypeError: # ignore exception in case ssl_cert is not set, thus None is attempted to expand.
  ssl_cert = None
#  make RWD optional in (sign|seal)key, if it is b'' then this protects against
#  offline master pwd bruteforce attacks, drawback that for known (host,username) tuples
#  the seeds/blobs can be controlled by an attacker if the masterkey is known
rwd_keys = cfg['client'].get('rwd_keys', False)
validate_password = cfg['client'].get('validate_password',True)
userlist = cfg['client'].get('userlist', True)
threshold = int(cfg['client'].get('threshold') or "1")
ts_epsilon = 1200 # todo make configurable
servers = cfg.get('servers',{})
delete_upgraded = False
if v1sphinx.enabled:
    delete_upgraded = cfg['client'].get('delete_upgraded',False)

if len(servers)>1:
    if threshold < 2:
        print('if you have multiple servers in your config, you must specify a threshold >1 also')
        exit(1)
    if len(servers)<threshold:
        print(f'threshold({threshold}) must be less or equal than the number of servers({len(servers)}) in your config')
        exit(1)
elif threshold > 1:
    print(f'threshold({threshold}) must be less or equal than the number of servers({len(servers)}) in your config')
    exit(1)

if verbose:
    print("hostname:", hostname, file=sys.stderr)
    print("address:", address, file=sys.stderr)
    print("port:", port, file=sys.stderr)
    print("datadir:", datadir, file=sys.stderr)
    print("ssl_cert:", ssl_cert, file=sys.stderr)
    print("rwd_keys:", rwd_keys, file=sys.stderr)
    print("validate_password:", validate_password, file=sys.stderr)
    print("userlist:", userlist, file=sys.stderr)
    print("threshold:", threshold, file=sys.stderr)
    for name, server in servers.items():
      print(f"{name} {server.get('host','localhost')}:{server.get('port', 2355)} {server['ltsigkey']} cert: {server.get('ssl_cert')}")

#### consts ####

ENC_CTX = b"sphinx encryption key"
SIGN_CTX = b"sphinx signing key"
SALT_CTX = b"sphinx host salt"
PASS_CTX = b"sphinx password context"
CHECK_CTX = b"sphinx check digit context"

#### Helper fns ####

def get_masterkey():
  try:
    with open(os.path.join(datadir,'masterkey'), 'rb') as fd:
        mk = fd.read()
    return mk
  except FileNotFoundError:
    raise ValueError("ERROR: Could not find masterkey!\nIf sphinx was working previously it is now broken.\nIf this is a fresh install all is good, you just need to run `%s init`." % sys.argv[0])

def get_signkey(id, rwd):
  mk = get_masterkey()
  seed = pysodium.crypto_generichash(SIGN_CTX, mk)
  clearmem(mk)
  # rehash with rwd so the user always contributes his pwd and the sphinx server it's seed
  seed = pysodium.crypto_generichash(seed, id)
  if rwd_keys:
    seed = pysodium.crypto_generichash(seed, rwd)
  pk, sk = pysodium.crypto_sign_seed_keypair(seed)
  clearmem(seed)
  return sk, pk

def get_sealkey():
  mk = get_masterkey()
  sk = pysodium.crypto_generichash(ENC_CTX, mk)
  clearmem(mk)
  return sk

def encrypt_blob(blob):
  # todo implement padding to hide length information
  sk = get_sealkey()
  nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
  ct = pysodium.crypto_aead_xchacha20poly1305_ietf_encrypt(blob,VERSION,nonce,sk)
  clearmem(sk)
  return VERSION+nonce+ct

def decrypt_blob(blob):
  # todo implement padding to hide length information
  sk = get_sealkey()
  version = blob[:1]
  if version > VERSION:
    raise ValueError("Your client is too old to handle this response. Please update your client.")
  blob = blob[1:]
  nonce = blob[:pysodium.crypto_secretbox_NONCEBYTES]
  blob = blob[pysodium.crypto_secretbox_NONCEBYTES:]
  res = pysodium.crypto_aead_xchacha20poly1305_ietf_decrypt(blob,version,nonce,sk)
  clearmem(sk)
  return version, res

def sign_blob(blob, id, rwd):
  sk, pk = get_signkey(id, rwd)
  res = pysodium.crypto_sign_detached(blob,sk)
  clearmem(sk)
  return b''.join((blob,res))

def getsalt():
  mk = get_masterkey()
  salt = pysodium.crypto_generichash(SALT_CTX, mk)
  clearmem(mk)
  return salt

def getid1(host,user,peer,salt=None):
  if salt is None: salt = getsalt()
  user_len = struct.pack('!H', len(user))
  host_len = struct.pack('!H', len(host))
  peer_len = struct.pack('!H', len(peer))
  return pysodium.crypto_generichash(b''.join((user_len,user.encode(),
                                               host_len,host.encode(),
                                               peer_len,peer.encode())), salt, 32)
def getid(host, user, m):
  salt = getsalt()
  ids = []
  for peer in m:
    ids.append(getid1(host,user,peer.name,salt))
  return ids

def oprf2rwd(r, beta, pwd, host, user):
  rwd = pyoprf.unblind_finalize(r, beta, pwd)
  salt = pysodium.crypto_generichash(getsalt()
                                     + struct.pack('!H', len(user.encode('utf8')))
                                     + user.encode('utf8')
                                     + struct.pack('!H', len(host.encode('utf8')))
                                     + host.encode('utf8'),
                                     outlen=pysodium.crypto_pwhash_SALTBYTES)
  return pysodium.crypto_pwhash(pyoprf.OPRF_BYTES, rwd, salt, pysodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, pysodium.crypto_pwhash_MEMLIMIT_INTERACTIVE)

def unpack_rule(ct):
  version, packed = decrypt_blob(ct)
  xor_mask = packed[-64:]
  v = int.from_bytes(packed[:-64], "big")

  size = v & ((1<<7) - 1)
  rule = {c for i,c in enumerate(('u','l','d')) if (v >> 7) & (1 << i)}
  symbols = [c for i,c in enumerate(bin2pass.symbols) if (v>>(7+3) & (1<<i))]
  if validate_password:
      check_digit = (v>>(7+3+33))
  else:
      check_digit = 0

  return rule, symbols, size, check_digit, xor_mask

def pack_rule(char_classes, syms, size, check_digit, xor_mask=None, with_schema=False):
  # pack rules into and encrypt them
  if set(char_classes) - {'u','l','d'}:
    raise ValueError("ERROR: rules can only contain any of 'uld'.")
  if set(syms) - set(bin2pass.symbols) != set():
    raise ValueError("ERROR: symbols can only contain any of '%s'." % bin2pass.symbols)
  if not with_schema and (char_classes == '' and len(syms)<2):
    raise ValueError("ERROR: no char classes and not enough symbols specified.")
  if not with_schema and (xor_mask is None and (char_classes == '' and len(syms)<2)):
    raise ValueError("ERROR: no char classes and not enough symbols specified.")
  if xor_mask is None:
      xor_mask = b'\x00' * 64
  elif len(xor_mask)!=64:
    raise ValueError("ERROR: xor_mask must be 64bytes, is instead: %d." % len(xor_mask))
  if size<0 or size>127:
    raise ValueError("ERROR: invalid max password size: %d." % size)

  packed = size
  packed = packed + (sum(1<<i for i, c in enumerate(('u','l','d')) if c in char_classes) << 7)
  packed = packed + (sum(1<<i for i, c in enumerate(bin2pass.symbols) if c in syms) << (7 + 3))
  packed = packed + ((check_digit & ((1<<5) - 1)) << (7 + 3 + 33) )
  pt = packed.to_bytes(6,"big") + xor_mask
  return encrypt_blob(pt)

def xor(x,y):
  return bytes(a ^ b for (a, b) in zip(x, y))

def commit_undo(m, op, pwd, user, host):
  ids = getid(host, user,m)
  r, alpha = pyoprf.blind(pwd)
  msgs = [b''.join([op, id, alpha]) for id in ids]
  m = ratelimit(m, msgs)
  if not auth(m,ids,host,user,alpha,pwd,r):
    m.close()
    raise ValueError("Failed to authenticate to server while %s" % "committing" if op == COMMIT else "undoing")
  if set(m.gather(2))!={b'ok'}:
    m.close()
    raise ValueError("Server failed to %s" % "Commit" if op == COMMIT else "UNDO")
  m.close()
  return True

def read_pkt(s,size):
    res = []
    read = 0
    while read<size or len(res[-1])==0:
      res.append(s.recv(size-read))
      read+=len(res[-1])

    return b''.join(res)

def update_rec(s, id, item): # this is only for user blobs. a UI feature offering a list of potential usernames.
    if not userlist:
        s.send(b"\0"*96)
        return
    signed_id = sign_blob(id, id, b'')
    s.send(signed_id)
    # wait for user blob
    bsize = s.recv(2)
    bsize = struct.unpack('!H', bsize)[0]
    if bsize == 0:
      # it is a new blob, we need to attach an auth signing pubkey
      sk, pk = get_signkey(id, b'')
      clearmem(sk)
      # we encrypt with an empty rwd, so that the user list is independent of the master pwd
      blob = encrypt_blob(item.encode())
      bsize = len(blob)
      if bsize >= 2**16:
        s.close()
        raise ValueError("ERROR: list of usernames is bigger than 64KB. %d" % bsize)
      blob = struct.pack("!H", bsize) + blob
      # writes need to be signed, and sinces its a new blob, we need to attach the pubkey
      blob = b''.join([pk, blob])
      # again no rwd, to be independent of the master pwd
      blob = sign_blob(blob, id, b'')
    else:
      blob = read_pkt(s, bsize)
      if blob == b'fail':
        s.close()
        raise ValueError("reading list of user names failed")
      version, blob = decrypt_blob(blob)
      items = {x for x in blob.decode().split('\x00') if x}
      # this should not happen, but maybe it's a sign of corruption?
      if item in items:
        print(f'warning: "{item}" is already in the user record', file=sys.stderr)
      items.add(item)
      blob = ('\x00'.join(sorted(items))).encode()
      # notice we do not add rwd to encryption of user blobs
      blob = encrypt_blob(blob)
      bsize = len(blob)
      if bsize >= 2**16:
        s.close()
        raise ValueError("ERROR: list of user names is bigger than 64KB. %d" % bsize)
      blob = struct.pack("!H", bsize) + blob
      blob = sign_blob(blob, id, b'')
    s.send(blob)

def auth(m,ids,host,user,alpha=None,pwd=None,r=None):
  if r is None:
    nonces = m.gather(32)
    if nonces is None:
      m.close()
      return False
    nonces = list(enumerate(nonces))
    rwd = b''
  else:
    msgs = m.gather(65,proc=lambda x: (x[:33],x[33:]))
    if msgs is None:
      m.close()
      return False
    nonces = [(idx,resp[1]) for idx, resp in enumerate(msgs)]
    if len(msgs) < len(m):
        raise ValueError("auth: not all peers answered or authenticated")
    beta = pyoprf.thresholdmult([resp[0] for resp in msgs][:threshold])
    #rwd = pyoprf.unblind_finalize(r, beta, pwd)
    rwd = oprf2rwd(r, beta, pwd, host, user)

  for idx, nonce in nonces:
    sk, pk = get_signkey(ids[idx], rwd)
    sig = pysodium.crypto_sign_detached(nonce,sk)
    clearmem(sk)
    m.send(idx, sig)

  clearmem(rwd)

  responses = m.gather(6)
  if responses is None:
    m.close()
    return False

  fails = 0
  for idx, resp in enumerate(responses):
    if resp==b'\x00\x04auth': continue
    if resp==b'\x00\x04fail':
      print(f'authentication failed for {m[idx].name}')
      m[idx].close()
      fails+=1
    else:
      raise ValueError("unexpected auth result")

  if fails > 0:
      raise ValueError("some peers have failed to authenticate us")

  return True

def ratelimit(m,reqs):
  for i, req in enumerate(reqs):
    pkt0 = b''.join([CHALLENGE_CREATE, req])
    m[i].send(pkt0)

  challenges = m.gather(1+1+8+32) # n,k,ts,sig
  if challenges is None:
    m.close()
    return False
  m.close()

  puzzles = []
  with concurrent.futures.ProcessPoolExecutor() as executor:
    for idx, challenge in enumerate(challenges):
        if challenge in {None, b''}: continue
        n = challenge[0]
        k = challenge[1]

        try:
            os.write(3,f"{idx} {n} {k}\n".encode('utf8'))
        except OSError: pass

        if k==4:
            if n < 90:
              if verbose: print(f"{m[idx].name} sent an easy puzzle: %d" % n, file=sys.stderr)
            elif n > 100:
              if verbose: print(f"{m[idx].name} sent a hard puzzle: %d" % n, file=sys.stderr)
            else:
              if verbose: print(f"{m[idx].name} sent a moderate puzzle: %d" % n, file=sys.stderr)
        seed = challenge + reqs[idx]

        solution = executor.submit(solve,n,k,seed)
        puzzles.append((challenge, solution, idx))

  for puzzle in puzzles:
    m[puzzle[2]].connect()
    pkt1 = b''.join([CHALLENGE_VERIFY, puzzle[0]])
    m.send(puzzle[2], pkt1)
    m.send(puzzle[2], reqs[puzzle[2]])
    m.send(puzzle[2], puzzle[1].result())
  return m

def getpwd():
  if sys.stdin.isatty():
    return getpass.getpass("enter your password please: ").encode('utf8')
  else:
    return sys.stdin.buffer.readline().rstrip(b'\n')

def dkg(m, op, threshold, keyids, alpha):
   n = len(m)

   # load peer long-term keys
   peer_lt_pks = []
   for name, server in servers.items():
      with open(server.get('ltsigkey'),'rb') as fd:
         peer_lt_pk = fd.read()
         if(len(peer_lt_pk)!=pysodium.crypto_sign_PUBLICKEYBYTES):
            raise ValueError(f"long-term signature key for server {name} is of incorrect size")
         peer_lt_pks.append(peer_lt_pk)


   if op == CREATE_DKG:
     tp, msg0 = pyoprf.tpdkg_start_tp(n, threshold, ts_epsilon, "threshold sphinx dkg create k", peer_lt_pks)
     for index, id in enumerate(keyids):
        msg = b"%c%s%s%s" % (CREATE_DKG, id, alpha, msg0)
        m.send(index,msg)
   else:
     tp, msg0 = pyoprf.tpdkg_start_tp(n, threshold, ts_epsilon, "threshold sphinx dkg change k", peer_lt_pks)
     msg = b"%s%s" % (alpha, msg0)
     m.broadcast(msg)

   while pyoprf.tpdkg_tp_not_done(tp):
     ret, sizes = pyoprf.tpdkg_tp_input_sizes(tp)
     peer_msgs = []
     if ret:
         if sizes[0] > 0:
             #print(f"step: {tp[0].step}")
             peer_msgs = m.gather(sizes[0],n) #,debug=True)
     else:
         peer_msgs = [m[i].read(s) if s>0 else b'' for i, s in enumerate(sizes)]
     msgs = b''.join(peer_msgs)

     cur_step = pyoprf.tpdkg_tpstate_step(tp)
     try:
       out = pyoprf.tpdkg_tp_next(tp, msgs)
     except Exception as e:
       m.close()
       if pyoprf.tpdkg_tpstate_cheater_len(tp) > 0:
         cheaters, cheats = pyoprf.tpdkg_get_cheaters(tp)
         msg=[f"Warning during the distributed key generation the peers misbehaved: {sorted(cheaters)}"]
         for k, v in cheats:
           msg.append(f"\tmisbehaving peer: {k} was caught: {v}")
         msg = '\n'.join(msg)
         raise ValueError(msg)
       else:
         raise ValueError(f"{e} | tp step {cur_step}")
     if(len(out)>0):
       for i in range(pyoprf.tpdkg_tpstate_n(tp)):
         msg = pyoprf.tpdkg_tp_peer_msg(tp, out, i)
         m.send(i, msg)

   betas = m.gather(33, n)
   if betas is None:
     m.close()
     raise ValueError(f"failed to get oprf responses from shareholders in final step of dkg")

   rwds = set(pyoprf.thresholdmult([betas[i] for i in order])
              for order in permutations(range(n),threshold))
   if len(rwds) != 1:
     raise ValueError("DKG shares are inconsistent, aborting operation.")

   return list(rwds)[0]

#### OPs ####

def init():
  init_browser_ext()
  kfile = os.path.join(datadir,'masterkey')
  if os.path.exists(kfile):
    print("Already initialized.", file=sys.stderr)
    return 1
  if not os.path.exists(datadir):
    os.makedirs(datadir, 0o700, exist_ok=True)
  mk = pysodium.randombytes(32)
  try:
    with open(kfile,'wb') as fd:
      if not win: os.fchmod(fd.fileno(),0o600)
      fd.write(mk)
  except:
    print("ERROR: failed to initialize master key", file=sys.stderr)
    return 1
  finally:
    print("you want to make a backup of the following masterkey, keep it safe and secure", binascii.b2a_base64(mk))
    print('this key is also stored - and must be available - at:', kfile)
    clearmem(mk)
  return 0

def create(m, pwd, user, host, char_classes='uld', symbols=bin2pass.symbols, size=0, target=None):
  # 1st step OPRF on the new seed
  ids = getid(host, user, m)
  r, alpha = pyoprf.blind(pwd)
  if threshold > 1:
    beta = dkg(m, CREATE_DKG, threshold, ids, alpha)
  else:
    msg = b''.join([CREATE, ids[0], alpha])
    m.broadcast(msg)

    # wait for response from sphinx server
    beta = m.gather(33)
    if beta is None:
      m.close()
      raise ValueError("ERROR: Creating new password, the record probably already exists or the first message to server was corrupted during transport.")
      # or (less probable) the initial message was longer/shorter than the 65 bytes we sent
      # or (even? less probable) the value alpha received by the server is not a valid point
      # both of these less probable causes point at corruption during transport
    beta = beta[0][1:]

  #rwd = pyoprf.unblind_finalize(r, beta, pwd)
  rwd = oprf2rwd(r, beta, pwd, host, user)

  # second phase, derive new auth signing pubkey
  sign_keys=[]
  for id in ids:
    sk, pk = get_signkey(id, rwd)
    clearmem(sk)
    sign_keys.append(pk)

  if validate_password:
      checkdigit = pysodium.crypto_generichash(CHECK_CTX, rwd, 1)[0]
  else:
      checkdigit = 0

  if target and not user.startswith('raw://'):
    trwd, char_classes, symbols = bin2pass.pass2bin(target, None)
    xormask = xor(pysodium.crypto_generichash(PASS_CTX, rwd, outlen=64),trwd)
    size = len(target)
    #char_classes = 'uld'
    #symbols = bin2pass.symbols
  elif target and user.startswith('raw://'):
    size = len(target)
    target = target + pysodium.randombytes(64 - len(target))
    xormask = xor(pysodium.crypto_generichash(PASS_CTX, rwd, outlen=64),target)
  else:
    _uppers = set([x.decode('utf8') for x in bin2pass.sets['u']])
    _lowers = set([x.decode('utf8') for x in bin2pass.sets['l']])
    _digits = set([x.decode('utf8') for x in bin2pass.sets['d']])
    _symbols = set(symbols)
    while True:
        xormask = pysodium.randombytes(64)
        candidate = convert(
            xor(pysodium.crypto_generichash(PASS_CTX, rwd, outlen=64),xormask),
            user,
            char_classes,size,symbols)
        if 1 <= size < 8: break # too much of a bias especially for ulsd when size < 5
        if 'u' in char_classes and len(_uppers.intersection(candidate)) == 0:
            continue
        if 'l' in char_classes and len(_lowers.intersection(candidate)) == 0:
            continue
        if 'd' in char_classes and len(_digits.intersection(candidate)) == 0:
            continue
        if len(_symbols) > 0 and len(_symbols.intersection(candidate)) == 0:
            continue
        break

  rule = pack_rule(char_classes, symbols, size, checkdigit, xormask, with_schema='://' in user)
  # send over new signed(pubkey, rule)
  for i,(id,pk) in enumerate(zip(ids, sign_keys)):
    msg = b''.join([pk, rule])
    msg = sign_blob(msg, id, rwd)
    m[i].send(msg)

  # add user to user list for this host
  # a malicous server could correlate all accounts on this services to this users here
  for p in m:
     id = getid1(host, '', p.name)
     update_rec(p.fd, id, user)
     p.close()

  rwd = xor(pysodium.crypto_generichash(PASS_CTX, rwd, outlen=64),xormask)

  ret = convert(rwd,user,char_classes,size,symbols)
  clearmem(rwd)
  return ret

def try_v1get(pwd, host, user):
   rwd = v1sphinx.get(pwd, user, host)
   # lift to v2
   m = Multiplexer(servers)
   m.connect()
   crwd = create(m, pwd, user, host, target=rwd)
   assert rwd == crwd
   print(f"updated v1 record to v2, for {user}@{host}", file=sys.stderr)
   if delete_upgraded:
       v1sphinx.delete(pwd, user, host)
       print(f"deleted v1 for {user}@{host} record after update to v2", file=sys.stderr)
   return rwd

def get(m, pwd, user, host):
  ids = getid(host, user, m)
  r, alpha = pyoprf.blind(pwd)

  msgs = [b''.join([GET, id, alpha]) for id in ids]
  try:
      m = ratelimit(m, msgs)
  except ValueError:
    if v1sphinx.enabled: return try_v1get(pwd, host, user)
    raise

  connected = sum([1 for p in m if p.state == 'connected'])
  if connected < threshold:
    raise ValueError(f"Failed to get enough shareholders to respond: {connected} responded")

  if len(servers) > 1:
    try:
      resps = m.gather(33+RULE_SIZE, threshold)
    except ValueError:
      if v1sphinx.enabled: return try_v1get(pwd, host, user)
      raise
    if resps is None:
      m.close()
      raise ValueError("Failed to get any answers from shareholders")
    if len({x for x in resps if x is not None}) == 1 and {x for x in resps if x is not None} == {b'\x00\x04fail'}:
      raise ValueError("ERROR: The record does not exist, there's a chance you are being fished.")
    resps = [(x[:33], x[33:]) for x in resps if x is not None]
    if len({resp[1] for resp in resps if resp}) != 1:
      m.close()
      raise ValueError("ERROR: servers disagree on rules")
    rules = resps[0][1]
    beta = pyoprf.thresholdmult([resp[0] for resp in resps if resp])
  else:
    try:
        resp = m.gather(33+RULE_SIZE, 1)[0] # beta + sealed rules
    except ValueError:
      if v1sphinx.enabled: return try_v1get(pwd, host, user)
      raise
    if resp is None:
      m.close()
      raise ValueError("Failed to get answers from sphinx server")
    if resp == b'\x00\x04fail':
      raise ValueError("ERROR: The record does not exist, there's a chance you are being fished.")
    if len(resp)!=33+RULE_SIZE:
      m.close()
      raise ValueError("ERROR: the request to server was corrupted during transport.")
    beta = resp[1:33]
    rules = resp[33:]

  #rwd = pyoprf.unblind_finalize(r, beta, pwd)
  rwd = oprf2rwd(r, beta, pwd, host, user)

  m.close()
  try:
    classes, symbols, size, checkdigit, xormask = unpack_rule(rules)
  except ValueError:
    m.close()
    raise ValueError("ERROR: failed to unpack password rules from server")

  if validate_password and (checkdigit != (pysodium.crypto_generichash(CHECK_CTX, rwd, 1)[0] & ((1<<5)-1))):
    m.close()
    raise ValueError("ERROR: bad checkdigit")

  rwd = xor(pysodium.crypto_generichash(PASS_CTX, rwd, outlen=64),xormask)

  ret = convert(rwd,user,classes,size,symbols)
  clearmem(rwd)

  return ret

def read_blob(m, ids, host, rwd = b''):
  msgs = [b''.join([READ, id]) for id in ids]
  m = ratelimit(m, msgs)

  if auth(m,ids,host,'') is False:
    m.close()
    return

  bsizes = set(m.gather(2, proc = lambda x: struct.unpack('!H', x)[0]))
  if bsizes is None:
    m.close()
    raise ValueError("failed to get sizes for user blobs from threshold servers")
  if len(bsizes) != 1:
    m.close()
    raise ValueError(f"ERROR: inconsistent user list blob sizes: {bsizes}")
  bsize = list(bsizes)[0]
  #print('got all blobsizes')
  if bsize == 0:
    # this should not happen, it means something is corrupt
    m.close()
    raise ValueError("ERROR: server has no associated user record for this host", file=sys.stderr)

  blobs = m.gather(bsize)
  if blobs is None:
    m.close()
    raise ValueError("failed to read user blobs from sphinx servers")
  #print('got all blobs')
  ptblobs = set()
  for blob in blobs:
    if blob == b'fail':
      m.close()
      raise ValueError("ERROR: invalid signature on list of users")
    ptblobs.add(decrypt_blob(blob))

  if len(ptblobs)!=1:
    raise ValueError(f"ERROR: inconsistent user list blobs")
  blob = list(ptblobs)[0]

  return blob

def users(m, host):
  _, users = read_blob(m, getid(host, '', m), host) or (None, set())
  if users:
      users = set(users.decode().split('\x00'))
  if v1sphinx.enabled:
      try: v1users = v1sphinx.users(host)
      except: v1users = set()
      users = users | v1users
  if not users:
      return "no users found"
  return '\n'.join(sorted(users))

def change(m, oldpwd, newpwd, user, host, classes='uld', symbols=bin2pass.symbols, size=0, target=None):
  ids = getid(host, user, m)
  r, alpha = pyoprf.blind(oldpwd)

  if threshold > 1:
    msgs = [b''.join([CHANGE_DKG, id, alpha]) for id in ids]
  else:
    msgs = [b''.join([CHANGE, id, alpha]) for id in ids]
  m = ratelimit(m, msgs)
  # auth: do sphinx with current seed, use it to sign the nonce
  if not auth(m,ids,host,user,alpha,oldpwd,r):
    m.close()
    raise ValueError("ERROR: Failed to authenticate using old password to server while changing password on server or record doesn't exist")

  r, alpha = pyoprf.blind(newpwd)
  if threshold > 1:
    beta = dkg(m, CHANGE_DKG, threshold, None, alpha)
  else:
    m.broadcast(alpha)
    beta = m.gather(33,1) # beta
    if beta is None or len(beta[0])!=33:
      m.close()
      raise ValueError("ERROR: changing password failed due to corruption during transport.")
    beta = beta[0][1:]
  #rwd = pyoprf.unblind_finalize(r, beta, newpwd)
  rwd = oprf2rwd(r, beta, newpwd, host, user)

  if validate_password:
      checkdigit = pysodium.crypto_generichash(CHECK_CTX, rwd, 1)[0]
  else:
      checkdigit = 0

  if target:
    trwd, classes, symbols = bin2pass.pass2bin(target, None)
    xormask = xor(pysodium.crypto_generichash(PASS_CTX, rwd, outlen=64),trwd)
    print('asdf', len(trwd), len(xormask))
    size = len(target)
  else:
    xormask = pysodium.randombytes(64)

  rule = pack_rule(classes, symbols, size, checkdigit, xormask)

  for i, id in enumerate(ids):
    sk, pk = get_signkey(id, rwd)
    clearmem(sk)
    # send over new signed(pubkey)
    m[i].send(sign_blob(b''.join([pk,rule]), id, rwd))

  if set(m.gather(2))!={b'ok'}:
    m.close()
    raise ValueError("ERROR: failed to update password rules on the server during changing of password.")

  m.close()
  rwd = xor(pysodium.crypto_generichash(PASS_CTX, rwd, outlen=64),xormask)
  ret = convert(rwd,user,classes,size,symbols)
  clearmem(rwd)

  return ret

def commit(s, pwd, user, host):
  return commit_undo(s, COMMIT, pwd, user, host)

def undo(s, pwd, user, host):
  return commit_undo(s, UNDO, pwd, user, host)

def delete(m, pwd, user, host):
  # run sphinx to recover rwd for authentication
  ids = getid(host, user, m)
  r, alpha = pyoprf.blind(pwd)
  msgs = [b''.join([DELETE, id, alpha]) for id in ids]
  m = ratelimit(m, msgs)
  #print("solved ratelimit puzzles")
  if auth(m,ids,host,user,alpha,pwd,r) is False:
    m.close()
    raise ValueError("ERROR: Failed to authenticate to server while deleting password on server or record doesn't exist")
  #print("authenticated")

  if not userlist:
     m.broadcast(b"\0"*96)
  else:
     # delete user from user list for this host
     # a malicous server could correlate all accounts on this services to this users here
     # first query user record for this host
     for p in m:
        id = getid1(host, '', p.name)
        signed_id = sign_blob(id, id, b'')
        p.send(signed_id)

     # wait for user blob
     bsizes = set(m.gather(2, proc = lambda x: struct.unpack('!H', x)[0]))
     if bsizes is None:
       m.close()
       raise ValueError("failed to get sizes for user blobs from threshold servers")
     if len(bsizes) != 1:
       m.close()
       raise ValueError(f"ERROR: inconsistent user list blob sizes: {bsizes}")
     bsize = list(bsizes)[0]
     #print('got all blobsizes')
     if bsize == 0:
       # this should not happen, it means something is corrupt
       m.close()
       raise ValueError("ERROR: server has no associated user record for this host", file=sys.stderr)

     blobs = m.gather(bsize)
     if blobs is None:
       m.close()
       raise ValueError("failed to read user blobs from sphinx servers")
     #print('got all blobs')
     ptblobs = set()
     for blob in blobs:
       if blob == b'fail':
         m.close()
         raise ValueError("ERROR: invalid signature on list of users")
       ptblobs.add(decrypt_blob(blob))

     if len(ptblobs)!=1:
       raise ValueError(f"ERROR: inconsistent user list blobs")
     version, blob = list(ptblobs)[0]

     users = set(blob.decode().split('\x00'))
     if user not in users:
       # this should not happen, but maybe it's a sign of corruption?
       m.close()
       raise ValueError(f'warning "{user}" is not in user record', file=sys.stderr)
     users.remove(user)
     blob = ('\x00'.join(sorted(users))).encode()
     # notice we do not add rwd to encryption of user blobs
     for p in m:
       xblob = encrypt_blob(blob)
       bsize = len(xblob)
       if bsize >= 2**16:
           m.close()
           raise ValueError("ERROR: blob is bigger than 64KB.")
       xblob = struct.pack("!H", bsize) + xblob
       id = getid1(host, '', p.name)
       xblob = sign_blob(xblob, id, b'')
       #print(f'updating {p.name}\t{xblob.hex()}')
       p.send(xblob)

     if set(m.gather(2))!={b'ok'}:
       m.close()
       raise ValueError("ERROR: server failed to save updated list of user names for host: %s." % host)

  m.close()
  return True

def print_qr(qrcode: QrCode) -> None:
  chars = {
    (True, True):    ' ',      # empty
    (False, True):   '\u2580', # upper
    (True, False):   '\u2584', # lower
    (False, False):  '\u2588', # full
  }
  border = 1
  for y in range(-border, qrcode.get_size() + border, 2):
    for x in range(-border, qrcode.get_size() + border):
      print(chars[(qrcode.get_module(x,y),qrcode.get_module(x,y+1))], end="")
    print()
  print()


def qrcode(output, key):
  mk=get_masterkey() if key else b''
  hosts = []
  for name, server in servers.items():
    if len(name)>255: raise ValueError(f"server name: {name} is too long, max 255 allowed in qr codes")
    hosts.append(bytes([len(name.encode('utf8'))]) + name.encode('utf8') +
                 bytes([len(server.get('host','localhost'))]) + server.get('host','localhost').encode('utf8') +
                 struct.pack("!H", server.get('port', 2355)))
  hosts=zlib.compress(b''.join(hosts))
  data = (bytes([1*key+2*rwd_keys + 4*validate_password + 8*userlist + 16+delete_upgraded, threshold]) +
          mk +
          hosts)

  qr = QrCode.encode_binary(data, QrCode.Ecc.LOW)
  if key:
    clearmem(mk)
    clearmem(data)
  if output=='txt':
    print_qr(qr)
  else:
    print(qr.to_svg_str(2))

def ostore_handler(m, pwd, params, newpwd=None):
    op, keyid, args = ostore.parse(params)
    user = keyid
    host = 'opaque store'

    if op == ostore.changepwd:
        args.insert(0, {'m': Multiplexer,
                        'servers': servers,
                        'change': change,
                        'commit': commit,
                        'user': user,
                        'host': host,
                        'pwd': pwd,
                        'newpwd': newpwd})
    elif op == ostore.erase:
        args.insert(0, {'m': Multiplexer,
                        'servers': servers,
                        'delete': delete,
                        'pwd': pwd,
                        'user': user,
                        'host': host})

    if op == ostore.store:
        rwd = create(m, pwd, user, host)
    else:
        rwd = get(m, pwd, user, host)
    op(rwd, keyid, *args)

    return True

def usage(params, help=False):
  print("usage:")
  print("SPHINX style passwords")
  print("       %s init" % params[0])
  print("       echo -n 'password' | %s <create|change> <user> <site> <[u][l][d][s] [<size>] [<symbols>]> | [<target password>]" % params[0])
  print("       echo -n 'password' | %s get <user> <site>" % params[0])
  if rwd_keys: print("       echo -n 'password' | %s <commit|undo|delete> <user> <site>" % params[0])
  else: print("       %s <commit|undo|delete> <user> <site>" % params[0])
  if userlist: print("       %s list <site>" % params[0])
  print("       %s qr [svg] [key]" % params[0])
  if ostore.available:
      ostore.usage(params)
  if help: sys.exit(0)
  sys.exit(100)

def arg_rules(params):
  user = params[2]
  site = params[3]
  size = None
  symbols = None
  classes = None
  target = None
  for param in params[4:]:
    if not classes and set(list(param)) - {'u','l','s','d'} == set():
      if 's' in param:
        symbols = bin2pass.symbols
        classes = ''.join(set(param) - set(['s']))
      else:
        classes = param
        symbols = ''
      continue
    if not size:
      try:
        tmp = int(param)
        if tmp<79:
          size = tmp
          continue
      except: pass
    if set(param) - set(bin2pass.symbols) == set():
      symbols = param
      continue
    if verbose: print(f'using "{param}" as target password', file=sys.stderr)
    target = param
  if target is not None and (symbols or classes or size):
    print(f"invalid args for {param[1]}: \"{params[4:]}\"", file=sys.stderr)
    usage(param)
  return user, site, classes or 'uld', symbols if symbols is not None else bin2pass.symbols, size or 0, target

def test_pwd(pwd):
  if zxcvbn is None: return
  q = zxcvbn(pwd.decode('utf8'))
  print("your %s%s (%s/4) master password can be online recovered in %s, and offline in %s, trying ~%s guesses" %
        ("★" * q['score'],
         "☆" * (4-q['score']),
         q['score'],
         q['crack_times_display']['online_throttling_100_per_hour'],
         q['crack_times_display']['offline_slow_hashing_1e4_per_second'],
         q['guesses']), file=sys.stderr)

#### main ####

def main(params=sys.argv):
  #import ctypes
  #libc = ctypes.cdll.LoadLibrary('libc.so.6')
  #fdopen = libc.fdopen
  #log_file = ctypes.c_void_p.in_dll(pyoprf.liboprf,'log_file')
  #fdopen.restype = ctypes.c_void_p
  #log_file.value = fdopen(2, 'w')

  if len(params) < 2: usage(params, True)
  m = Multiplexer(servers)
  cmd = None
  args = []
  if params[1] in ('help', '-h', '--help'):
    usage(params, True)
  elif params[1] == 'create':
    try:
      user,site,classes, syms, size, target = arg_rules(params)
    except: usage(params)
    cmd = create
    args = (user, site, classes, syms, size, target)
  elif params[1] == 'init':
    if len(params) != 2: usage(params)
    sys.exit(init())
  elif params[1] == 'get':
    if len(params) != 4: usage(params)
    cmd = get
    args = (params[2], params[3])
  elif params[1] == 'change':
    try:
      user,site,classes,syms,size, target = arg_rules(params)
    except: usage(params)
    cmd = change
    args = (user, site, classes, syms, size, target)
  elif params[1] == 'commit':
    if len(params) != 4: usage(params)
    cmd = commit
    args = (params[2], params[3])
  elif params[1] == 'delete':
    if len(params) != 4: usage(params)
    cmd = delete
    args = (params[2], params[3])
  elif userlist and params[1] == 'list':
    if len(params) != 3: usage(params)
    cmd = users
    args = (params[2],)
  elif params[1] == 'undo':
    if len(params) != 4: usage(params)
    cmd = undo
    args = (params[2],params[3])
  elif params[1] == 'qr':
    cmd = qrcode
    output = 'txt'
    key = False
    if "svg" in params:
      output="svg"
      del params[params.index("svg")]
    if "key" in params:
      key=True
      del params[params.index("key")]
    if params[2:]: usage(params)
    qrcode(output, key)
    return
  elif ostore.available and ostore.is_cmd(params):
    cmd = ostore_handler
    args = [params]
  else:
    usage(params)

  error = None
  if cmd != users:
    pwd = ''
    if (rwd_keys or cmd in {create,change,get, ostore_handler}):
      pwd = getpwd()
      if cmd == change or (cmd == ostore_handler and params[1] == 'changepwd'):
        newpwd = getpwd()
        if not newpwd:
          newpwd = pwd
        test_pwd(newpwd)
        if cmd == change:
            args=(newpwd,) + args
        else:
            args=args + [newpwd]
      if cmd == create:
        test_pwd(pwd)
    try:
      m.connect()
      ret = cmd(m, pwd, *args)
    except Exception as exc:
      error = exc
      ret = False
      raise # only for dbg
    clearmem(pwd)
  else:
    try:
      m.connect()
      ret = cmd(m,  *args)
    except Exception as exc:
      error = exc
      ret = False
      raise # only for dbg
  m.close()

  if not ret:
    if not error:
        print("fail", file=sys.stderr)
        sys.exit(3) # error not handled by exception
    print(error, file=sys.stderr)
    if str(error) == "ERROR: bad checkdigit":
      sys.exit(2) # bad check digit
    sys.exit(1) # generic errors

  if cmd not in {delete, undo, commit, ostore_handler}:
    print(ret)
    sys.stdout.flush()
    clearmem(ret)
  elif ret != True:
    print("reached code that should not be reachable: ", ret)

if __name__ == '__main__':
  try:
    main(sys.argv)
  except Exception:
    print("fail", file=sys.stderr)
    raise # only for dbg
