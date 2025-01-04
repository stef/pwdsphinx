#!/usr/bin/env python3
#
# This file is part of WebSphinx.
#
# SPDX-FileCopyrightText:  2018, Marsiske Stefan <pitchfork@ctrlc.hu>
# SPDX-License-Identifier:  GPL-3.0-or-later
#
# WebSphinx is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation either version 3 of the License, or
# (at your option) any later version.
#
# WebSphinx is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License version 3 for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, If not, see <http://www.gnu.org/licenses/>.


import subprocess
import sys, struct, json, pysodium
import cbor2
from zxcvbn import zxcvbn
from SecureString import clearmem
from pyoprf.multiplexer import Multiplexer
from binascii import b2a_base64
from base64 import urlsafe_b64decode
try:
    from pwdsphinx import sphinx, bin2pass
    from pwdsphinx.config import getcfg
except ImportError:
    import sphinx
    from config import getcfg

cfg = getcfg('sphinx')
pinentry = cfg['websphinx']['pinentry']
log = cfg['websphinx'].get('log')

if 'webauthn_data_dir' not in cfg['websphinx']:
    raise Exception("Cannot find webauthn user directory (webauthn_data_dir). Add it to your config file")

webauthn_data_dir = cfg['websphinx']['webauthn_data_dir']

def handler(cb, cmd, *args):
    m = Multiplexer(sphinx.servers)
    m.connect()
    cb(cmd(m, *args))
    m.close()

def getpwd(title):
    proc=subprocess.Popen([pinentry, '-g'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(input=('SETTITLE sphinx password prompt\nSETDESC %s\nSETPROMPT master password\ngetpin\n' % (title)).encode())
    if proc.returncode == 0:
        for line in out.split(b'\n'):
            if line.startswith(b"D "): return line[2:]

def fetchOK(proc, cmd):
    proc.stdin.write(f"{cmd}\n".encode("utf8"))
    proc.stdin.flush()
    if((line:=proc.stdout.readline())!=b"OK\n"):
        raise ValueError(f"fail \"{cmd}\": {line}")

def pwdq(pwd):
    q = zxcvbn(pwd.decode('utf8'))
    q['guesses']
    q['score']
    q['crack_times_display']
    q['feedback']

    proc=subprocess.Popen([pinentry, '-g'],
                          stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)

    if not (resp:=proc.stdout.readline()).startswith(b'OK Pleased to meet you'):
        raise ValueError(f"strange greeting \"{resp}\"")
    fetchOK(proc ,"SETTITLE Password Quality Check")
    fetchOK(proc ,"SETOK use this")
    fetchOK(proc ,"SETCANCEL try another")
    fetchOK(proc ,"SETDESC your %s%s (%s/4) master password:%%0a - can be online recovered in %s,%%0a - offline in %s,%%0a - trying ~%s guesses%%0a%%0aAre you sure you want to use this password?" %
            ("★" * q['score'],
             "☆" * (4-q['score']),
             q['score'],
             q['crack_times_display']['online_throttling_100_per_hour'],
             q['crack_times_display']['offline_slow_hashing_1e4_per_second'],
             q['guesses']))
    try:
        fetchOK(proc ,"CONFIRM")
    except ValueError:
        return False
    return True

# Send message using Native messaging protocol
def send_message(data):
  msg = json.dumps(data).encode('utf-8')
  if log:
    log.write(msg)
    log.write(b'\n')
    log.flush()
  length = struct.pack('@I', len(msg))
  sys.stdout.buffer.write(length)
  sys.stdout.buffer.write(msg)
  sys.stdout.buffer.flush()

def users(data):
  def callback(users):
    res = {'names': [i for i in users.split("\n")],
           'cmd': 'list', "mode": data['mode'], 'site': data['site']}
    send_message({ 'results': res })

  try:
    handler(callback, sphinx.users, data['site'])
  except:
    send_message({ 'results': 'fail' })

def get(data):
  def callback(arg):
    res = { 'password': arg, 'name': data['name'], 'site': data['site'], 'cmd': 'login', "mode": data['mode']}
    send_message({ 'results': res })
  try:
    pwd=getpwd("get password for user \"%s\" at host \"%s\"" % (data['name'], data['site']))
    handler(callback, sphinx.get, pwd, data['name'], data['site'])
  except:
    send_message({ 'results': 'fail' })

def create(data):
  def callback(arg):
    res = { 'password': arg, 'name': data['name'], 'site': data['site'], 'cmd': 'create', "mode": data['mode']}
    send_message({ 'results': res })
  try:
    pwd=None
    while not pwd:
        pwd=getpwd("create password for user \"%s\" at host \"%s\"%%0a" % (data['name'], data['site']))
        pwd2=getpwd("REPEAT: create for user \"%s\" at host \"%s\"%%0a" % (data['name'], data['site']))
        if pwd != pwd2:
            send_message({ 'results': 'fail' })
            return
        if not pwdq(pwd): pwd=None

    symbols = ''
    if 's' in data['rules']:
      symbols = bin2pass.symbols
      data['rules'] = ''.join(set(data['rules']) - set(['s']))
    handler(callback, sphinx.create, pwd, data['name'], data['site'], data['rules'], symbols, int(data['size']), None)
  except:
    send_message({ 'results': 'fail' })

def change(data):
  def callback(arg):
    res = { 'password': arg, 'name': data['name'], 'site': data['site'], 'cmd': 'change', "mode": data['mode']}
    send_message({ 'results': res })
  try:
    oldpwd=""
    if cfg['client'].get('rwd_keys'):
        oldpwd=getpwd("current password for \"%s\" at host: \"%s\"%%0a" % (data['name'], data['site']))
    pwd=None
    while not pwd:
        pwd=getpwd("new password for user \"%s\" at host \"%s\"%%0a" % (data['name'], data['site']))
        pwd2=getpwd("REPEAT: new for user \"%s\" at host \"%s\"%%0a" % (data['name'], data['site']))
        if pwd != pwd2:
            send_message({ 'results': 'fail' })
            return
        if not pwdq(pwd): pwd=None

    symbols = ''
    if 's' in data['rules']:
      symbols = bin2pass.symbols
      data['rules'] = ''.join(set(data['rules']) - set(['s']))
    handler(callback, sphinx.change, oldpwd, pwd, data['name'], data['site'], data['rules'], symbols, int(data['size']), None)
  except:
    send_message({ 'results': 'fail' })

def commit(data):
  def callback(arg):
    res = { 'result': arg, 'name': data['name'], 'site': data['site'], 'cmd': 'commit', "mode": data['mode']}
    send_message({ 'results': res })
  try:
    pwd=""
    if cfg['client'].get('rwd_keys'):
      pwd=getpwd("commit password for \"%s\" at host: \"%s\"%%0a" % (data['name'], data['site']))
    handler(callback, sphinx.commit, pwd, data['name'], data['site'])
  except:
    send_message({ 'results': 'fail' })

def undo(data):
  def callback(arg):
    res = { 'result': arg, 'name': data['name'], 'site': data['site'], 'cmd': 'undo', "mode": data['mode']}
    send_message({ 'results': res })
  try:
    pwd=""
    if cfg['client'].get('rwd_keys'):
      pwd=getpwd("undo password for \"%s\" at host: \"%s\"%%0a" % (data['name'], data['site']))
    handler(callback, sphinx.undo, pwd, data['name'], data['site'])
  except:
    send_message({ 'results': 'fail' })

def qrcode(data):
  try:
    sphinx.qrcode("svg", True)
    res = { 'result': arg, 'cmd': 'qrcode', "mode": data['mode']}
    send_message({ 'results': res })
  except:
    send_message({ 'results': 'fail' })


def echo(data):
    send_message(data)

def webauthn_create(data):
  try:
    pwd=None
    while not pwd:
        pwd=getpwd("create password for user \"%s\" at host \"%s\"%%0a" % (data['name'], data['site']))
        pwd2=getpwd("REPEAT: create for user \"%s\" at host \"%s\"%%0a" % (data['name'], data['site']))
        if pwd != pwd2:
            send_message({ 'results': 'fail', 'id': data['id'], 'tabId': data['tabId'], 'cmd': res['cmd']})
            return
        if not pwdq(pwd): pwd=None
    # TODO use webauthn:// instead of raw:// - don't forget to rewrite it in handle()
    rand_bytes = pysodium.randombytes(32)
    pk, sk = pysodium.crypto_sign_seed_keypair(rand_bytes)
    # signed_challenge = pysodium.crypto_sign(data['challenge'], sk)
    auth_data = pysodium.crypto_hash_sha256(data['site'].encode('utf8')) + ( # rpIdHash
        b'\x4d' + # flags https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data
        b'\x00' * 4 + # signCount
        b'\x00' * 16 + # attestedCredentialData->AAGUID
        struct.pack('>H', len(pk)) + # attestedCredentialData->pk length
        pk + # attestedCredentialData->credentialId (pk)
        cbor2.dumps({ # cose encoded public key https://datatracker.ietf.org/doc/html/rfc8152#section-13
            1: 1, # key type => okp
            3: -8, # algorithm => Ed25519 (-8)
            -1: 6, # curve => ed25519
            -2: pk, # x => pubkey
            # no y required (y is -3)
    })) # attestedCredentialData->credentialPublicKey

    # TODO use opaque
    with open(webauthn_data_dir + "/" + pk.hex(), "wb") as wf:
        wf.write(urlsafe_b64decode(data['userid']+"=="))

    att_sig =  pysodium.crypto_sign_detached(auth_data + pysodium.crypto_hash_sha256(data['clientDataJSON'].encode('utf-8')), sk)

    attestation = cbor2.dumps({
        'fmt': 'packed',
        'attStmt': {
            'alg': -8,
            'sig': att_sig,
        },
        'authData': auth_data
    })
    #log.write((data['clientDataJSON']+"\n").encode('utf-8'))
    #log.write((auth_data.hex() + "\n").encode('utf-8'))

    res = {
        'pk': b2a_base64(pk).decode('utf8').strip(),
        'attestationObject': b2a_base64(attestation).decode('utf-8').strip(),
        'authData': b2a_base64(auth_data).decode('utf-8').strip(),
        'name': data['name'],
        'site': data['site'],
        'cmd': 'webauthn-create',
        'id': data['id'],
        'tabId': data['tabId']
    }

    # create new user with pk
    m = Multiplexer(sphinx.servers)
    m.connect()
    # TODO add optional argument to create() to skip extending the userlist
    orig_userlist = sphinx.userlist
    sphinx.userlist = False
    sphinx.create(m, pwd, 'raw://'+pk.hex(), data['site'], '', '', target = rand_bytes)
    sphinx.userlist = orig_userlist
    m.close()
    clearmem(sk)
    clearmem(rand_bytes)
    send_message({'results': res})
  except Exception as e:
      send_message({ 'results': 'fail', 'id': data.get('id', ''), 'tabId': data.get('tabId', -1), 'cmd': 'webauthn-create'})
      #send_message({ 'results': 'fail', 'id': data.get('id', ''), 'tabId': data.get('tabId', -1), 'cmd': 'webauthn-create', 'exception': str(e)})

def webauthn_get(data):
    def callback(rand_bytes):
        pk, sk = pysodium.crypto_sign_seed_keypair(rand_bytes)
        clearmem(rand_bytes)

        # TODO use opaque
        with open(webauthn_data_dir + "/" + pk.hex(), "rb") as wf:
            userid = wf.read()

        auth_data = pysodium.crypto_hash_sha256(data['site'].encode('utf8')) + ( # rpIdHash
            b'\x4d' + # flags https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data
            b'\x00' * 4 + # signCount
            b'\x00' * 16 + # attestedCredentialData->AAGUID
            struct.pack('>H', len(pk)) + # attestedCredentialData->pk length
            pk + # attestedCredentialData->credentialId (pk)
            cbor2.dumps({ # cose encoded public key https://datatracker.ietf.org/doc/html/rfc8152#section-13
                1: 1, # key type => okp
                3: -8, # algorithm => Ed25519 (-8)
                -1: 6, # curve => ed25519
                -2: pk, # x => pubkey
                # no y required (y is -3)
        })) # attestedCredentialData->credentialPublicKey
        sig = pysodium.crypto_sign_detached(auth_data + pysodium.crypto_hash_sha256(data['clientDataJSON'].encode('utf-8')), sk)
        clearmem(sk)

        res = {
            'userid': b2a_base64(userid).decode('utf-8').strip(),
            'sig': b2a_base64(sig).decode('utf8').strip(),
            'authData': b2a_base64(auth_data).decode('utf-8').strip(),
            'site': data['site'],
            'cmd': 'webauthn-get',
            'id': data['id'],
            'tabId': data['tabId'],
            'pk': b2a_base64(pk).decode('utf-8').strip(),
        }
        send_message({'results': res})
    try:
        pwd=getpwd("get webauthn password at host \"%s\"" % data['site'])
        pk = urlsafe_b64decode(data['pk']+"==")
        handler(callback, sphinx.get, pwd, 'raw://'+pk.hex(), data['site'])
    except Exception as e:
        send_message({ 'results': 'fail', 'id': data.get('id', ''), 'tabId': data.get('tabId', -1), 'cmd': 'webauthn-get'})
        #send_message({ 'results': 'fail', 'id': data.get('id', ''), 'tabId': data.get('tabId', -1), 'cmd': 'webauthn-get', 'exception': str(e)})


func_map = {
    'login': get,
    'list': users,
    'create': create,
    'change': change,
    'commit': commit,
    'undo': undo,
    'qrcode': qrcode,
    'echo': echo,
    'webauthn-create': webauthn_create,
    'webauthn-get': webauthn_get,
}


def main():
  global log
  if log: log = open(log,'ab')
  while True:
    # Read message using Native messaging protocol
    length_bytes = sys.stdin.buffer.read(4)
    if len(length_bytes) == 0:
      return

    length = struct.unpack('i', length_bytes)[0]
    data = json.loads(sys.stdin.buffer.read(length).decode('utf-8'))

    if log:
      log.write(repr(data).encode())
      log.write(b'\n')
      log.flush()

    if data['cmd'] in func_map:
        func_map[data['cmd']](data)
    else:
        send_message({ 'results': 'fail' })

if __name__ == '__main__':
  main()
