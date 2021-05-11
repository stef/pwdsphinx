#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2018, 2021, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
from binascii import hexlify

#from itertools import chain
#tuple(bytes([x]) for x in chain(range(32,48),range(58,65),range(91,97),range(123,127)))
symbols = ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'

sets = {
    # symbols
    # digits
    'd': tuple(bytes([x]) for x in range(48,58)),
    # upper-case
    'u': tuple(bytes([x]) for x in range(65,91)),
    # lower-case
    'l': tuple(bytes([x]) for x in range(97,123))}

def encode(raw, chars):
    v = int(hexlify(raw),16)
    char_size = len(chars)
    out = []
    while(v>char_size):
        v, r = divmod(v, char_size)
        out += chars[r]
    return bytes(out)

def derive(rwd, rule, size, syms=symbols):
    chars = tuple(c for x in (sets[c] for c in ('u','l','d') if c in rule) for c in x) + tuple(x.encode('utf8') for x in symbols if x in set(syms))
    password = encode(rwd,chars)
    if size>0: password=password[:size]
    return password

def usage():
    print("usage: %s [d|u|l] [<max size>] \" !\"#$%%&'()*+,-./:;<=>?@[\\]^_`{|}~\" <binary\tgenerate password with [d]igits/[u]pper/[l]ower of <max size> {default: uld}" % sys.argv[0])
    sys.exit(0)

def main():
  if len(sys.argv)>4 or 'h' in sys.argv or '--help' in sys.argv:
    usage()

  if len(sys.argv)==2: # figure out if set or size
    if sys.argv[1]=='s':
      print("all symbols:", symbols)
      return

  size = 0
  raw = sys.stdin.buffer.read(32)
  syms = symbols
  rule = 'uld'

  for arg in sys.argv[1:]:
    try:
      size = int(arg)
      continue
    except ValueError: pass
    # a symbol set specification?
    if set(arg) - set(symbols) == set():
      syms = set(arg)
    elif set(arg) - set("uld") == set():
      rule = arg
    else:
      usage()

  if size<0:
    print("error size must be < 0")
    usage()

  print(derive(raw,rule,size,syms).decode("utf8"))

if __name__ == '__main__':
  main()
