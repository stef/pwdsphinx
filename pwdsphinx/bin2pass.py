#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2018, 2021, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import sys, math, random

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

allchars = ''.join(tuple(c.decode('utf8') for x in (sets[c] for c in ('u','l','d') if c in 'uld') for c in x) + tuple(symbols))

def bin2pass(raw, chars, size):
    v = int.from_bytes(raw, 'big')
    result = ''
    while (size > 0 and len(result) < size) or (size == 0 and v > 0):
        idx = v % len(chars)
        v //= len(chars)
        result = chars[idx] + result
    return result

def pass2bin(string, chars = allchars):
    classes = {'u','l','d'}
    sym = symbols
    # reduce char classes to necessary minimum to
    # accomodate longer passwords
    if chars == None:
        chars = []
        for c in ('u','l','d'):
            s = set(x.decode('utf8') for x in sets[c])
            if s & set(string):
                chars.append(''.join(sorted(s)))
            else:
                classes.remove(c)
        if set(string) & set(symbols):
            chars+=symbols
        else:
            sym = ''
        chars=''.join(chars)

    le_str = string[::-1]
    logbase = int(math.log(1<<256, len(chars)))
    r = sum(chars.find(le_str[i]) * len(chars)**i for i in range(len(le_str)))
    # add padding
    r += sum(chars.find(random.choice(chars)) * len(chars)**i for i in range(len(le_str), logbase))
    return int.to_bytes(r, 32, 'big'), ''.join(classes), sym

def derive(rwd, rule, size, syms=symbols):
    chars = tuple(c.decode('utf8') for x in (sets[c] for c in ('u','l','d') if c in rule) for c in x) + tuple(x for x in symbols if x in set(syms))
    password = bin2pass(rwd,chars, size)
    if size>0: password=password[:size]
    return password

def usage():
    print("usage: %s [d|u|l] [<max size>] \" !\"#$%%&'()*+,-./:;<=>?@[\\]^_`{|}~\" <binary\tgenerate password with [d]igits/[u]pper/[l]ower of <max size> {default: uld}" % sys.argv[0])
    sys.exit(0)

def main():
  if len(sys.argv)>4 or 'h' in sys.argv or '--help' in sys.argv:
    usage()

  if len(sys.argv)==2:
    if sys.argv[1]=='s':
      print("all symbols:", symbols)
      return

  size = 0
  raw = sys.stdin.buffer.read(32)
  syms = symbols
  rule = ''

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

  print(derive(raw,rule,size,syms))

if __name__ == '__main__':
  main()
