#!/usr/bin/env python

from pwdsphinx import bin2pass
import traceback, os, sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

converters = {}

def load_converters():
  global converters
  p = Path(__file__).parent.absolute()
  for converter_fname in os.listdir(f'{p}/converters/'):
    if converter_fname.startswith('_') or not converter_fname.endswith('.py'):
        continue
    try:
      name = converter_fname[:-3]
      import_path = 'converters.'+name
      if import_path in sys.modules:
          del sys.modules[import_path]
      s = SourceFileLoader(import_path,
                           f'{p}/converters/' + converter_fname).load_module()
    except:
      print("failed to load converter", converter_fname)
      traceback.print_exc()
      continue
    for schema, converter in s.schema.items():
      if schema in converters:
        raise ValueError(f"{schema} is a already in loaded converters")
      converters[schema]=converter

load_converters()

def convert(rwd, user, *opts):

  if '://' not in user:
    return bin2pass.derive(rwd, *opts)

  schema, _ = user.split("://",1)
  return converters[schema](rwd, *opts)

if __name__ == "__main__":
  convert(b'\xaa' * 32, 'asdf', 'uld', 0, '')
  import sys
  args = [int(x) if x.isdigit() else x for x in sys.argv[1:]]
  rwd = sys.stdin.buffer.read(32)
  print(convert(rwd, *args))
