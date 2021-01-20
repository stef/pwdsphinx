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
import sys, struct, json
try:
    from pwdsphinx import sphinx
    from pwdsphinx.config import getcfg
except ImportError:
    import sphinx
    from config import getcfg

cfg = getcfg('sphinx')
pinentry = cfg['websphinx']['pinentry']
log = cfg['websphinx']['log']

def handler(cb, cmd, *args):
    s = sphinx.connect()
    cb(cmd(s, *args))
    s.close()

def getpwd(title):
    proc=subprocess.Popen([pinentry, '-g'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(input=('SETTITLE sphinx %spassword prompt\nSETPROMPT sphinx %spassword\ngetpin\n' % (title,title)).encode())
    if proc.returncode == 0:
        for line in out.split(b'\n'):
            if line.startswith(b"D "): return line[2:]

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
    pwd=getpwd("current ")
    handler(callback, sphinx.get, pwd, data['name'], data['site'])
  except:
    send_message({ 'results': 'fail' })

def create(data):
  def callback(arg):
    res = { 'password': arg, 'name': data['name'], 'site': data['site'], 'cmd': 'create', "mode": data['mode']}
    send_message({ 'results': res })
  try:
    pwd=getpwd("")
    pwd2=getpwd("again")
    if pwd != pwd2:
        send_message({ 'results': 'fail' })
    else:
        handler(callback, sphinx.create, pwd, data['name'], data['site'], data['rules'], data['size'])
  except:
    send_message({ 'results': 'fail' })

def change(data):
  def callback(arg):
    res = { 'password': arg, 'name': data['name'], 'site': data['site'], 'cmd': 'change', "mode": data['mode']}
    send_message({ 'results': res })
  try:
    pwd=getpwd("new ")
    handler(callback, sphinx.change, pwd, data['name'], data['site'])
  except:
    send_message({ 'results': 'fail' })

def commit(data):
  def callback(arg):
    res = { 'result': arg, 'name': data['name'], 'site': data['site'], 'cmd': 'commit', "mode": data['mode']}
    send_message({ 'results': res })
  try:
    pwd=getpwd("")
    handler(callback, sphinx.commit, pwd, data['name'], data['site'])
  except:
    send_message({ 'results': 'fail' })

def undo(data):
  def callback(arg):
    res = { 'result': arg, 'name': data['name'], 'site': data['site'], 'cmd': 'undo', "mode": data['mode']}
    send_message({ 'results': res })
  try:
    pwd=getpwd("")
    handler(callback, sphinx.undo, pwd, data['name'], data['site'])
  except:
    send_message({ 'results': 'fail' })

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
    if data['cmd'] == 'login':
      get(data)
    elif data['cmd'] == 'list':
      users(data)
    elif data['cmd'] == 'create':
      create(data)
    elif data['cmd'] == 'change':
      change(data)
    elif data['cmd'] == 'commit':
      commit(data)
    elif data['cmd'] == 'undo':
      undo(data)

if __name__ == '__main__':
  main()
