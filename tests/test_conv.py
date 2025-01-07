#!/usr/bin/env python3

import unittest
from pwdsphinx.converter import convert
from pwdsphinx import bin2pass

char_classes = 'uld'
symbols = bin2pass.symbols
size = 0

class TestConverters(unittest.TestCase):
  def test_bin2pass(self):
    rwd = b'\xaa' * 32
    pwd = convert(rwd, "asdf", char_classes, size, symbols)
    self.assertEqual(pwd, '2UH@/%XoTb+T-RT*tipUqT+b\'lYQ*kUiPOdq@sK')

  def test_bin2pass_8char(self):
    rwd = b'\xaa' * 32
    pwd = convert(rwd, "asdf", char_classes, 8, symbols)
    self.assertEqual(pwd, 'iPOdq@sK')

  def test_raw(self):
    rwd = b'\xaa' * 32
    pwd = convert(rwd, "raw://asdf", char_classes, len(rwd), symbols)
    self.assertEqual(pwd, rwd)


  def test_otp(self):
    rwd = b'A' * 16
    pwd = convert(rwd, "otp://asdf", char_classes, size, symbols)
    self.assertIsInstance(pwd, str)
    self.assertEqual(len(pwd), 6)

  def test_age(self):
    rwd = b'\x55' * 32
    pwd = convert(rwd, "age://asdf", char_classes, size, symbols)
    self.assertEqual(pwd, 'AGE-SECRET-KEY-1242424242424242424242424242424242424242424242424242S6JN5PD')
    from pwdsphinx.converters.sphage import decode
    self.assertEqual(rwd, bytes(decode('age-secret-key-', pwd)))
