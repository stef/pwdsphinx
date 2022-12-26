#!/usr/bin/env python

import unittest, random, math
from pwdsphinx import bin2pass

# to get coverage, run
# PYTHONPATH=.. coverage run ../tests/pass2bin.py
# coverage report -m
# to just run the tests do
# python3 -m unittest discover --start-directory ../tests

class TestRules(unittest.TestCase):
    def test_invert_simple(self):
      target = "this is a pass2bin test string"
      rwd, classes, symbols = bin2pass.pass2bin(target)
      self.assertEqual(bin2pass.derive(rwd, classes, len(target), symbols), target)

    def test_invert_too_long(self):
      target = "this is a pass2bin test stringthis is a pass2bin test stringthis is a pass2bin test stringthis is a pass2bin test stringthis is a pass2bin test string"
      self.assertRaises(OverflowError, bin2pass.pass2bin, target)

    def test_invert_iter(self):
      chars = bin2pass.allchars
      for i in range(1,len(chars)):
        target=''.join(chars[:i])
        try:
          rwd, classes, symbols = bin2pass.pass2bin(target)
        except OverflowError:
          break
        self.assertEqual(bin2pass.derive(rwd, classes, len(target), symbols), target)

    def test_invert_reviter(self):
      chars = bin2pass.allchars
      for i in range(1,len(chars)):
        target=''.join(chars[-i:])
        try:
          rwd,classes, symbols = bin2pass.pass2bin(target)
        except OverflowError:
          break
        self.assertEqual(bin2pass.derive(rwd, classes, len(target), symbols), target)

    def test_invert_random(self):
      chars = bin2pass.allchars
      for _ in range(1000):
         target=''.join(random.choices(chars,k=random.randrange(1,39)))
         rwd,classes, symbols = bin2pass.pass2bin(target)
         self.assertEqual(bin2pass.derive(rwd, classes, len(target), symbols), target)

    def test_all_zeroes(self):
        logbase = int(math.log(1<<256, len(bin2pass.allchars)))
        target = bin2pass.allchars[0] * (logbase-1) + bin2pass.allchars[1]
        for _ in range(logbase):
          rwd,classes, symbols = bin2pass.pass2bin(target)
          self.assertEqual(bin2pass.derive(rwd, classes, len(target), symbols), target)
          target = target[1:]+bin2pass.allchars[0]

    def test_short_zeroes(self):
        logbase = int(math.log(1<<256, len(bin2pass.allchars)))
        target = bin2pass.allchars[0] * (logbase//2) + bin2pass.allchars[1]
        for _ in range(len(target)):
          ctarget = ''.join(target)
          (rwd,classes,symbols) = bin2pass.pass2bin(ctarget)
          self.assertEqual(bin2pass.derive(rwd, classes, len(ctarget), symbols), ctarget)
          target = target[1:]+bin2pass.allchars[0]

if __name__ == '__main__':
    unittest.main()
