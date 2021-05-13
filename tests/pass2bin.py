#!/usr/bin/env python

import unittest, random
from pwdsphinx import bin2pass

# to get coverage, run
# PYTHONPATH=.. coverage run ../tests/pass2bin.py
# coverage report -m
# to just run the tests do
# python3 -m unittest discover --start-directory ../tests

class TestRules(unittest.TestCase):
    def test_invert_simple(self):
      target = "this is a pass2bin test string"
      rwd = bin2pass.invert(target)
      self.assertEqual(bin2pass.derive(rwd, 'uld', len(target), bin2pass.symbols), target.encode('utf8'))

    def test_invert_too_long(self):
      target = "this is a pass2bin test stringthis is a pass2bin test stringthis is a pass2bin test stringthis is a pass2bin test stringthis is a pass2bin test string"
      self.assertIsNone(bin2pass.invert(target))

    def test_invert_iter(self):
      chars = tuple(c.decode('utf8') for x in (bin2pass.sets[c] for c in ('u','l','d') if c in 'uld') for c in x) + tuple(bin2pass.symbols)
      for i in range(1,len(chars)):
        target=''.join(chars[:i])
        rwd = bin2pass.invert(target)
        if not rwd: break
        self.assertEqual(bin2pass.derive(rwd, 'uld', len(target), bin2pass.symbols), target.encode('utf8'))

    def test_invert_reviter(self):
      chars = tuple(c.decode('utf8') for x in (bin2pass.sets[c] for c in ('u','l','d') if c in 'uld') for c in x) + tuple(bin2pass.symbols)
      for i in range(1,len(chars)):
        target=''.join(chars[-i:])
        rwd = bin2pass.invert(target)
        if not rwd: break
        self.assertEqual(bin2pass.derive(rwd, 'uld', len(target), bin2pass.symbols), target.encode('utf8'))

    def test_invert_random(self):
      chars = tuple(c.decode('utf8') for x in (bin2pass.sets[c] for c in ('u','l','d') if c in 'uld') for c in x) + tuple(bin2pass.symbols)
      for _ in range(10000):
         target=''.join(random.choices(chars,k=random.randrange(39)))
         rwd = bin2pass.invert(target)
         self.assertEqual(bin2pass.derive(rwd, 'uld', len(target), bin2pass.symbols), target.encode('utf8'))

if __name__ == '__main__':
    unittest.main()
