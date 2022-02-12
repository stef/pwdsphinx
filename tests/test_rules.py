import unittest
from os import listdir
from shutil import rmtree
from unittest.mock import Mock
from io import BytesIO
import sys, pysodium

from pwdsphinx import sphinx, bin2pass

# to get coverage, run
# PYTHONPATH=.. coverage run ../tests/rules.py
# coverage report -m
# to just run the tests do
# python3 -m unittest discover --start-directory ../tests

def equ(classes, syms, size, check, xor):
    unpacked = sphinx.unpack_rule(sphinx.pack_rule(classes, syms, size, check, xor))
    assert set(classes) == unpacked[0]
    assert list(syms) == unpacked[1]
    assert size == unpacked[2]
    if sphinx.validate_password:
        assert check == unpacked[3]
    else:
        assert 0 == unpacked[3]
    assert xor == unpacked[4]

from itertools import chain, combinations
def powerset(iterable):
    "powerset([1,2,3]) --> () (1,) (2,) (3,) (1,2) (1,3) (2,3) (1,2,3)"
    s = list(iterable)
    return chain.from_iterable(combinations(s, r) for r in range(len(s)+1))

class TestRules(unittest.TestCase):
    def test_rules(self):
       for cls in powerset('uld'):
           equ(''.join(cls), bin2pass.symbols, 64, 31, b'\x00'*32)
           if cls!=tuple():
               equ(''.join(cls), '', 64, 31, b'\x00'*32)

       equ('uld', bin2pass.symbols[:16], 64, 31, b'\x00'*32)
       equ('uld', bin2pass.symbols[16:], 64, 31, b'\x00'*32)

       equ('uld', bin2pass.symbols, 64, 31, b'\xff'*32)
       equ('uld', bin2pass.symbols, 64, 31, b'\xaa'*32)

       for i in range(128):
           equ('uld', bin2pass.symbols, i, 31, b'\xaa'*32)
       for i in range(32):
           equ('uld', bin2pass.symbols, 64, i, b'\xaa'*32)

if __name__ == '__main__':
    unittest.main()
