#!/usr/bin/env python

import os, subprocess
from tempfile import mkstemp
try:
    from opaquestore import client
    available = True
except:
    client = None
    available = False

if available:
    client.config = client.processcfg(client.getcfg('opaque-store'))

def usage(params):
  print("\nOPAQUE Store style blobs")
  print("       echo -n 'password' | %s store <keyid> file-to-store" % params[0])
  print("       echo -n 'password' | %s read <keyid>" % params[0])
  print("       echo -n 'password' | %s replace [force] <keyid> file-to-store" % params[0])
  print("       echo -n 'password' | %s edit [force] <keyid>" % params[0])
  print("       echo -n 'password' | %s changepwd [force] <keyid>" % params[0])
  print("       echo -n 'password' | %s erase [force] <keyid>" % params[0])
  print("       echo -n 'password' | %s recovery-tokens <keyid>" % params[0])
  print("       echo -n 'password' | %s unlock <keyid> <recovery-token>" % params[0])

def is_cmd(params):
    if params[1] not in cmds: return False
    return True

def connect():
  s = client.Multiplexer(client.config['servers'])
  s.connect()
  return s

def store(pwd, keyid, path):
  # create & recovery-tokens
  with open(path,'r') as fd:
    data = fd.read()
  s = connect()
  client.create(s, pwd, keyid.encode('utf8'), data.encode('utf8'))
  s = connect()
  token = client.get_recovery_tokens(s, pwd, keyid.encode('utf8'))
  print("successfully created opaque store record. Store the following recovery token, in case this record is locked")
  print(token)

def read(pwd, keyid):
  s = connect()
  print(client.get(s, pwd, keyid.encode('utf8')))

def replace(pwd, keyid, path, force=False):
  with open(path,'r') as fd:
    data = fd.read()
  s = connect()
  client.update(s, pwd, keyid.encode('utf8'), data.encode('utf8'), force)

def erase(pwd, keyid, ctx, force=False):
  s = connect()
  client.delete(s, pwd, keyid.encode('utf8'), force)
  # also handle delete sphinx record in case ostore.erase
  m = ctx['m'](ctx['servers'])
  m.connect()
  ctx['delete'](m, ctx['pwd'], ctx['user'], ctx['host'])

def changepwd(pwd, keyid, ctx, force=False):
  m = ctx['m'](ctx['servers'])
  m.connect()
  newpwd = ctx['change'](m, ctx['pwd'], ctx['newpwd'], ctx['user'], ctx['host'])

  s = connect()
  data = client.get(s, pwd, keyid.encode('utf8'))

  s = connect()
  client.delete(s, pwd, keyid.encode('utf8'), force)

  s = connect()
  client.create(s, newpwd, keyid.encode('utf8'), data.encode('utf8'))

  s = connect()
  token = client.get_recovery_tokens(s, newpwd, keyid.encode('utf8'))

  m = ctx['m'](ctx['servers'])
  m.connect()
  ctx['commit'](m, ctx['pwd'], ctx['user'], ctx['host'])
  print("Store the following recovery token, in case this record is locked")
  print(token)

def edit(pwd, keyid, force=False):
  if not os.path.exists('/dev/tty'):
      print("can only edit on systems that have /dev/tty, sorry")
      return False
  s = connect()
  data = client.get(s, pwd, keyid.encode('utf8'))
  fd, fname = mkstemp()
  fd = os.fdopen(fd,'w')
  fd.write(data)
  fd.close()
  tty = os.open("/dev/tty", os.O_RDWR|os.O_LARGEFILE)
  subprocess.run([os.environ.get("EDITOR"), fname], stdin=tty, stdout=tty, stderr=tty)
  with open(fname,"r") as fd:
    data = fd.read()
  os.unlink(fname)
  s = connect()
  client.update(s, pwd, keyid.encode('utf8'), data.encode('utf8'), force)

def recoverytoken(pwd, keyid):
  s = connect()
  token = client.get_recovery_tokens(s, pwd, keyid.encode('utf8'))
  print("Store the following recovery token, in case this record is locked")
  print(token)

def unlock(pwd, keyid, token):
  # unlock + get
  s = connect()
  client.unlock(s, token, keyid.encode('utf8'))
  s = connect()
  print(client.get(s, pwd, keyid.encode('utf8')))

cmds = {'store': store,
        'read': read,
        'replace': replace,
        'edit': edit,
        'changepwd': changepwd,
        'erase': erase,
        'recovery-tokens': recoverytoken,
        'unlock': unlock}

def parse(params):
    if params[1] not in cmds: return False

    op = cmds[params[1]]
    args = []

    if params[1] in {'replace', 'edit', 'erase', 'changepwd'} and params[2]=='force':
        del params[2]
        args.append(True)

    keyid=params[2]

    if params[1] in {'store', 'replace'}:
        if not os.path.isfile(params[3]):
            raise ValueError(f'opaque store parameter "{params[3]}" is not a file, how would i store it?')
        args.insert(0, params[3])

    if params[1] == 'unlock':
        args.insert(0,params[3])

    return op, keyid, args
