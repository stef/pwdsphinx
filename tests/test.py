import unittest
from os import listdir
from shutil import rmtree
from unittest.mock import Mock
from io import BytesIO
import sys, pysodium

from pwdsphinx import sphinx, bin2pass

# to get coverage, run
# PYTHONPATH=.. coverage run ../tests/test.py
# coverage report -m
# to just run the tests do
# python3 -m unittest discover --start-directory ../tests

# disable the output of sphinx
sphinx.print = Mock()

data_dir = 'data/'
data_dir = '/home/s/tasks/sphinx/zphinx/data/'
orig_data_files = set(listdir(data_dir))
char_classes = 'uld'
syms = bin2pass.symbols
size = 0
pwd = 'asdf'
user = 'user1'
user2 = 'user2'
host = 'example.com'

class Input:
  def __init__(self, txt = None):
    if txt:
      self.buffer = BytesIO('\n'.join((pwd, txt)).encode())
    else:
      self.buffer = BytesIO(pwd.encode())

def cleanup():
  for f in listdir(data_dir):
    if f not in orig_data_files:
      rmtree(data_dir+f)

def bad_signkey(_, __):
  pk, sk = pysodium.crypto_sign_seed_keypair(b'\xfe'*pysodium.crypto_sign_SEEDBYTES)
  return sk, pk
get_signkey = sphinx.get_signkey

class TestEndToEnd(unittest.TestCase):
    def tearDown(self):
        cleanup()

    def test_create_user(self):
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, syms, size), str)

    def test_huge_user(self):
        with sphinx.connect() as s:
            self.assertRaises(ValueError, sphinx.create,s, pwd, 'a'*(2**16 - 40), host, char_classes, syms, size)
        with sphinx.connect() as s:
            rwd=sphinx.create(s, pwd, 'a'*(2**16 - 42), host, char_classes, syms, size)
            self.assertIsInstance(rwd, str)
        with sphinx.connect() as s:
            self.assertRaises(ValueError, sphinx.create, s, pwd, 'a', host, char_classes, syms, size)

    def test_rules_u(self):
        with sphinx.connect() as s:
            rwd = sphinx.create(s, pwd, user, host, "u", '', 0)
        self.assertIsInstance(rwd, str)
        self.assertTrue(rwd.isupper())

    def test_rules_l(self):
        with sphinx.connect() as s:
            rwd = sphinx.create(s, pwd, user, host, "l", '', 0)
        self.assertIsInstance(rwd, str)
        self.assertTrue(rwd.islower())

    def test_rules_d(self):
        with sphinx.connect() as s:
            rwd = sphinx.create(s, pwd, user, host, "d", '', 0)
        self.assertIsInstance(rwd, str)
        self.assertTrue(rwd.isdigit())

    def test_rules_ulsd(self):
        with sphinx.connect() as s:
            rwd = sphinx.create(s, pwd, user, host, char_classes, syms, 0)
        self.assertIsInstance(rwd, str)
        self.assertTrue(len(set([x.decode('utf8') for x in bin2pass.sets['u']]).intersection(rwd)) > 0)
        self.assertTrue(len(set([x.decode('utf8') for x in bin2pass.sets['l']]).intersection(rwd)) > 0)
        self.assertTrue(len(set([x.decode('utf8') for x in bin2pass.sets['d']]).intersection(rwd)) > 0)
        self.assertTrue(len(set(bin2pass.symbols).intersection(rwd)) > 0)

    def test_pwd_len(self):
        for i in range(1,32):
            with sphinx.connect() as s:
                rwd = sphinx.create(s, pwd, user, host, char_classes, syms, i)
                self.assertIsInstance(rwd, str)
                self.assertTrue(len(rwd)==i)
            with sphinx.connect() as s:
                self.assertTrue(sphinx.delete(s, pwd, user, host))

    def test_invalid_rules(self):
        with sphinx.connect() as s:
            self.assertRaises(ValueError, sphinx.create, s, pwd, user, host, "asdf", syms, size)

    def test_recreate_user(self):
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, syms, size), str)

        with sphinx.connect() as s:
            self.assertRaises(ValueError, sphinx.create,s, pwd, user, host, char_classes, syms, size)

    def test_get(self):
        with sphinx.connect() as s:
            rwd0 = sphinx.create(s, pwd, user, host, char_classes, syms, size)
            self.assertIsInstance(rwd0, str)

        s = sphinx.connect()
        rwd = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(rwd, str)

        self.assertEqual(rwd,rwd0)

    def test_get_inv_mpwd(self):
        with sphinx.connect() as s:
            rwd0 = sphinx.create(s, pwd, user, host, char_classes, syms, size)
            self.assertIsInstance(rwd0, str)

        with sphinx.connect() as s:
            self.assertRaises(ValueError, sphinx.get, s, 'zxcv', user, host)

    def test_get_nonexistant_host(self):
        with sphinx.connect() as s:
            self.assertRaises(ValueError, sphinx.get, s, pwd, user, host)

    def test_delete(self):
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, syms, size), str)

        with sphinx.connect() as s:
            self.assertTrue(sphinx.delete(s, pwd, user, host))

    def test_delete_inv_mpwd(self):
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, syms, size), str)

        with sphinx.connect() as s:
            self.assertIsNone(sphinx.delete(s, 'zxcv', user, host))

    def test_change(self):
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, syms, size), str)

        with sphinx.connect() as s:
            pwd0 = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(pwd0, str)

        with sphinx.connect() as s:
            pwd1 = sphinx.change(s, pwd, pwd, user, host)
        self.assertIsInstance(pwd1, str)
        self.assertNotEqual(pwd0, pwd1)

        with sphinx.connect() as s:
            pwd2 = sphinx.change(s, pwd, pwd.upper(), user, host)
        self.assertIsInstance(pwd2, str)
        self.assertNotEqual(pwd0, pwd2)
        self.assertNotEqual(pwd1, pwd2)

    def test_commit_undo(self):
        # create
        with sphinx.connect() as s:
            pwd0 = sphinx.create(s, pwd, user, host, char_classes, syms, size)
        self.assertIsInstance(pwd0, str)

        # get
        with sphinx.connect() as s:
            pwd1 = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(pwd1, str)
        self.assertEqual(pwd0, pwd1)

        # change
        with sphinx.connect() as s:
            pwd2 = sphinx.change(s, pwd, pwd.upper(), user, host)
        self.assertIsInstance(pwd2, str)
        self.assertNotEqual(pwd1, pwd2)

        # get
        with sphinx.connect() as s:
            pwd3 = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(pwd3, str)
        self.assertEqual(pwd1, pwd3)

        # commit
        with sphinx.connect() as s:
            sphinx.commit(s, pwd, user, host)
        with sphinx.connect() as s:
            pwd4 = sphinx.get(s, pwd.upper(), user, host)
        self.assertIsInstance(pwd4, str)
        self.assertEqual(pwd2, pwd4)

        # undo
        with sphinx.connect() as s:
            sphinx.undo(s, pwd.upper(), user, host, )
        with sphinx.connect() as s:
            pwd5 = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(pwd5, str)
        self.assertEqual(pwd1, pwd5)

    def test_commit_undo_inv_mpwd(self):
        # create
        with sphinx.connect() as s:
            pwd0 = sphinx.create(s, pwd, user, host, char_classes, syms, size)
            self.assertIsInstance(pwd0, str)

        # change invalid mpwd
        with sphinx.connect() as s:
           self.assertRaises(ValueError, sphinx.change,s, 'zxcv', pwd, user, host)

        # change correct mpwd
        with sphinx.connect() as s:
           pwd2 = sphinx.change(s, pwd, pwd, user, host)
        self.assertIsInstance(pwd2, str)
        self.assertNotEqual(pwd0, pwd2)

        # commit invalid mpwd
        with sphinx.connect() as s:
           self.assertRaises(ValueError, sphinx.commit,s, 'zxcv', user, host)

        # commit correct mpwd
        with sphinx.connect() as s:
           sphinx.commit(s, pwd, user, host)
        with sphinx.connect() as s:
           pwd4 = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(pwd4, str)
        self.assertEqual(pwd2, pwd4)

        # undo invalid mpwd
        with sphinx.connect() as s:
           self.assertRaises(ValueError, sphinx.undo,s, 'zxcv', user, host)

        # undo correct mpwd
        with sphinx.connect() as s:
           sphinx.undo(s, pwd, user, host)
        with sphinx.connect() as s:
           pwd5 = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(pwd5, str)
        self.assertEqual(pwd0, pwd5)

    def test_list_users(self):
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, syms, size), str)
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user2, host, char_classes, syms, size), str)
        with sphinx.connect() as s:
            users = sphinx.users(s, host)
            self.assertIsInstance(users, str)
            self.assertEqual(users, '\n'.join((user,user2)))

    def test_list_users_diff_mpwd(self):
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, syms, size), str)
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, 'zxcv', user2, host, char_classes, syms, size), str)
        with sphinx.connect() as s:
            users = sphinx.users(s, host)
            self.assertIsInstance(users, str)
            self.assertEqual(users, '\n'.join((user,user2)))

    def test_double_commit(self):
        # create
        with sphinx.connect() as s:
            pwd0 = sphinx.create(s, pwd, user, host, char_classes, syms, size)
            self.assertIsInstance(pwd0, str)

        # change
        with sphinx.connect() as s:
            pwd2 = sphinx.change(s, pwd, pwd, user, host)
        self.assertIsInstance(pwd2, str)
        self.assertNotEqual(pwd0, pwd2)

        # commit
        with sphinx.connect() as s:
            sphinx.commit(s, pwd, user, host)
        with sphinx.connect() as s:
            pwd4 = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(pwd4, str)
        self.assertEqual(pwd2, pwd4)

        # commit
        with sphinx.connect() as s:
            self.assertRaises(ValueError, sphinx.commit,s, pwd, user, host)

    def test_auth(self):
        # create
        with sphinx.connect() as s:
            rwd = sphinx.create(s, pwd, user, host, char_classes, syms, size)
            self.assertIsInstance(rwd, str)
        sphinx.get_signkey = bad_signkey
        with sphinx.connect() as s:
             self.assertRaises(ValueError, sphinx.change, s, pwd, pwd, user, host, char_classes, syms, size)
        sphinx.get_signkey = get_signkey

    def test_userblob_auth_create(self):
        # create
        with sphinx.connect() as s:
            rwd = sphinx.create(s, pwd, user, host, char_classes, syms, size)
            self.assertIsInstance(rwd, str)
        sphinx.get_signkey = bad_signkey
        with sphinx.connect() as s:
            self.assertRaises(ValueError, sphinx.create, s, pwd, user2, host, char_classes, syms, size)
        sphinx.get_signkey = get_signkey

    def test_create_user_xormask(self):
        with sphinx.connect() as s:
          rwd = sphinx.create(s, pwd, user, host, '', '', 0, pwd)
        self.assertIsInstance(rwd, str)
        self.assertEqual(pwd, rwd)

    def test_change_xormask(self):
        with sphinx.connect() as s:
          rwd0 = sphinx.create(s, pwd, user, host, char_classes, syms, size)
          self.assertIsInstance(rwd0, str)

        with sphinx.connect() as s:
            rwd1 = sphinx.change(s, pwd, pwd, user, host, '', '', 0, pwd)
        self.assertIsInstance(rwd1, str)
        self.assertEqual(rwd1, pwd)

        with sphinx.connect() as s:
            rwd2 = sphinx.change(s, pwd, pwd, user, host, '', '', 0, pwd+pwd)
        self.assertIsInstance(rwd2, str)
        self.assertEqual(rwd2, pwd+pwd)

    def test_main_create(self):
        sys.stdin = Input()
        self.assertIsNone(sphinx.main(('sphinx.py', 'create', user, host, char_classes, syms, str(size))))

    def test_main_get(self):
        sys.stdin = Input()
        self.assertIsNone(sphinx.main(('sphinx.py', 'create', user, host, char_classes, syms, str(size))))
        sys.stdin = Input()
        self.assertIsNone(sphinx.main(('sphinx.py', 'get', user, host)))

    def test_main_delete(self):
        sys.stdin = Input()
        self.assertIsNone(sphinx.main(('sphinx.py', 'create', user, host, char_classes, syms, str(size))))
        sys.stdin = Input()
        self.assertIsNone(sphinx.main(('sphinx.py', 'delete', user, host)))

    def test_main_change_commit_undo(self):
        sys.stdin = Input("qwer")
        self.assertIsNone(sphinx.main(('sphinx.py', 'create', user, host, char_classes, syms, str(size))))
        sys.stdin = Input()
        self.assertIsNone(sphinx.main(('sphinx.py', 'change', user, host, char_classes, syms, str(size))))
        sys.stdin = Input()
        self.assertIsNone(sphinx.main(('sphinx.py', 'commit', user, host)))
        sys.stdin = Input()
        self.assertIsNone(sphinx.main(('sphinx.py', 'undo', user, host)))

    def test_main_inv_params(self):
        for cmd in ('create','get','change','commit','undo','delete','list'):
            self.assertRaises(SystemExit, sphinx.main, ('sphinx.py', cmd))

if __name__ == '__main__':
    unittest.main()
