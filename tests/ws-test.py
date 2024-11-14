#!/usr/bin/env python

import struct, json, sys, subprocess

if sys.argv[1]=="get":
    msg = {'cmd': "login"}
else:
    msg = {'cmd': sys.argv[1]}

if sys.argv[1] in ('create', 'get', 'change', 'commit', 'undo', 'delete'):
    msg['name']= sys.argv[2]
    msg['site']= sys.argv[3]

if sys.argv[1] in {'create', 'change'}:
    msg['rules']= sys.argv[4]
    msg['size']= sys.argv[5]

if sys.argv[1] == 'list':
    msg['site']= sys.argv[2]

msg['mode'] = 'ws-test'
if sys.argv[1] == 'json':
    msg = sys.argv[2].replace("'", '"')
else:
    msg = json.dumps(msg)

print("cmd:", msg)
cmd = struct.pack('i', len(msg))+msg.encode("utf-8")
proc=subprocess.Popen(["../pwdsphinx/websphinx.py"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = proc.communicate(input=cmd)
print("ret", proc.returncode)
print("stdout")
for line in out.split(b'\n'):
    print(line)
print("stderr")
for line in err.split(b'\n'):
    print(line)
