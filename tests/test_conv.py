#!/usr/bin/env python3

import unittest
from pwdsphinx.converter import convert
from pwdsphinx.consts import *
from pwdsphinx import bin2pass

char_classes = 'uld'
symbols = bin2pass.symbols
size = 0

class TestConverters(unittest.TestCase):
  def test_bin2pass(self):
    rwd = b'\xaa' * 32
    pwd = convert(rwd, "asdf", "host", GET, char_classes, size, symbols)
    self.assertEqual(pwd, '2UH@/%XoTb+T-RT*tipUqT+b\'lYQ*kUiPOdq@sK')

  def test_bin2pass_8char(self):
    rwd = b'\xaa' * 32
    pwd = convert(rwd, "asdf", "host", GET, char_classes, 8, symbols)
    self.assertEqual(pwd, 'iPOdq@sK')

  def test_raw(self):
    rwd = b'\xaa' * 32
    pwd = convert(rwd, "raw://asdf", "host", GET, char_classes, len(rwd), symbols)
    self.assertEqual(pwd, rwd)

  def test_otp(self):
    pwd = 'A' * 16
    rwd, classes, symbols = bin2pass.pass2bin(pwd)
    pwd = convert(rwd, "otp://asdf", "host", GET, classes, len(pwd), symbols)
    self.assertIsInstance(pwd, str)
    self.assertEqual(len(pwd), 6)

  def test_age(self):
    rwd = b'\x55' * 32
    pwd = convert(rwd, "age://asdf", "host", GET, char_classes, size, symbols)
    self.assertEqual(pwd, 'AGE-SECRET-KEY-1242424242424242424242424242424242424242424242424242S6JN5PD')
    from pwdsphinx.converters.sphage import decode
    self.assertEqual(rwd, bytes(decode('age-secret-key-', pwd)))
