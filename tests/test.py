import unittest
from os import listdir
from shutil import rmtree
from unittest.mock import Mock
from io import BytesIO
import sys

from pwdsphinx import sphinx

# to get coverage, run
# PYTHONPATH=.. coverage run ../tests/test.py
# coverage report -m

# disable the output of sphinx
sphinx.print = Mock()

data_dir = 'data/'
orig_data_files = set(listdir(data_dir))
char_classes = 'ulsd'
size = 80
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


class TestEndToEnd(unittest.TestCase):

    def tearDown(self):
        cleanup()

    def test_create_user(self):
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, size), str)

    def test_invalid_rules(self):
        with sphinx.connect() as s:
            self.assertRaises(ValueError, sphinx.create, s, pwd, user, host, "asdf", size)

    def test_recreate_user(self):
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, size), str)

        with sphinx.connect() as s:
            self.assertRaises(ValueError, sphinx.create,s, pwd, user, host, char_classes, size)

    def test_get(self):
        with sphinx.connect() as s:
            rwd0 = sphinx.create(s, pwd, user, host, char_classes, size)
            self.assertIsInstance(rwd0, str)

        with sphinx.connect() as s:
            rwd = sphinx.get(s, pwd, user, host)
            self.assertIsInstance(rwd, str)

        self.assertEqual(rwd,rwd0)

    def test_get_inv_mpwd(self):
        with sphinx.connect() as s:
            rwd0 = sphinx.create(s, pwd, user, host, char_classes, size)
            self.assertIsInstance(rwd0, str)

        with sphinx.connect() as s:
            rwd = sphinx.get(s, 'zxcv', user, host)
            self.assertNotEqual(rwd0,rwd)

    def test_get_nonexistant_host(self):
        with sphinx.connect() as s:
            self.assertRaises(ValueError, sphinx.get, s, pwd, user, host)

    def test_delete(self):
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, size), str)

        with sphinx.connect() as s:
            self.assertTrue(sphinx.delete(s, pwd, user, host))

    def test_delete_inv_mpwd(self):
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, size), str)

        with sphinx.connect() as s:
            self.assertIsNone(sphinx.delete(s, 'zxcv', user, host))

    def test_change(self):
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, size), str)

        with sphinx.connect() as s:
            pwd0 = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(pwd0, str)

        with sphinx.connect() as s:
            pwd1 = sphinx.change(s, pwd, user, host)
        self.assertIsInstance(pwd1, str)
        self.assertNotEqual(pwd0, pwd1)

    def test_commit_undo(self):
        # create
        with sphinx.connect() as s:
            pwd0 = sphinx.create(s, pwd, user, host, char_classes, size)
            self.assertIsInstance(pwd0, str)

        # get
        with sphinx.connect() as s:
            pwd1 = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(pwd1, str)

        # change
        with sphinx.connect() as s:
            pwd2 = sphinx.change(s, pwd, user, host)
        self.assertIsInstance(pwd2, str)
        self.assertNotEqual(pwd1, pwd2)

        # get
        with sphinx.connect() as s:
            pwd3 = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(pwd3, str)
        self.assertEqual(pwd1, pwd3)

        # commit
        with sphinx.connect() as s:
            pwd4 = sphinx.commit(s, pwd, user, host, )
        self.assertIsInstance(pwd4, str)
        self.assertEqual(pwd2, pwd4)

        # undo
        with sphinx.connect() as s:
            pwd5 = sphinx.undo(s, pwd, user, host, )
        self.assertIsInstance(pwd5, str)
        self.assertEqual(pwd1, pwd5)

    def test_commit_undo_inv_mpwd(self):
        # create
        with sphinx.connect() as s:
            pwd0 = sphinx.create(s, pwd, user, host, char_classes, size)
            self.assertIsInstance(pwd0, str)

        # change invalid mpwd
        with sphinx.connect() as s:
           self.assertRaises(ValueError, sphinx.change,s, 'zxcv', user, host)

        # change correct mpwd
        with sphinx.connect() as s:
           pwd2 = sphinx.change(s, pwd, user, host)
        self.assertIsInstance(pwd2, str)
        self.assertNotEqual(pwd0, pwd2)

        # commit invalid mpwd
        with sphinx.connect() as s:
           self.assertRaises(ValueError, sphinx.commit,s, 'zxcv', user, host)

        # commit correct mpwd
        with sphinx.connect() as s:
           pwd4 = sphinx.commit(s, pwd, user, host, )
        self.assertIsInstance(pwd4, str)
        self.assertEqual(pwd2, pwd4)

        # undo invalid mpwd
        with sphinx.connect() as s:
           self.assertRaises(ValueError, sphinx.undo,s, 'zxcv', user, host)

        # undo correct mpwd
        with sphinx.connect() as s:
           pwd5 = sphinx.undo(s, pwd, user, host, )
        self.assertIsInstance(pwd5, str)
        self.assertEqual(pwd0, pwd5)

    def test_list_users(self):
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, size), str)
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user2, host, char_classes, size), str)
        with sphinx.connect() as s:
            users = sphinx.users(s, host)
            self.assertIsInstance(users, str)
            self.assertEqual(users, '\n'.join((user,user2)))

    def test_list_users_diff_mpwd(self):
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, size), str)
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, 'zxcv', user2, host, char_classes, size), str)
        with sphinx.connect() as s:
            users = sphinx.users(s, host)
            self.assertIsInstance(users, str)
            self.assertEqual(users, '\n'.join((user,user2)))

    def test_write(self):
        test_str = 'some test string'
        with sphinx.connect() as s:
            self.assertTrue(sphinx.write(s, '\n'.join((pwd, test_str)).encode(), user, host))

    def test_write_list(self):
        test_str = 'some test string'
        with sphinx.connect() as s:
           self.assertTrue(sphinx.write(s, '\n'.join((pwd, test_str)).encode(), user, host))
        with sphinx.connect() as s:
           self.assertTrue(sphinx.write(s, '\n'.join((pwd, test_str)).encode(), user2, host))
        with sphinx.connect() as s:
           users = sphinx.users(s, host)
           self.assertIsInstance(users, str)
           self.assertEqual(users, '\n'.join((user,user2)))

    def test_write_list_diff_mpwd(self):
        test_str = 'some test string'
        with sphinx.connect() as s:
           self.assertTrue(sphinx.write(s, '\n'.join((pwd, test_str)).encode(), user, host))
        with sphinx.connect() as s:
           self.assertTrue(sphinx.write(s, '\n'.join(('zxcv', test_str)).encode(), user2, host))
        with sphinx.connect() as s:
           users = sphinx.users(s, host)
           self.assertIsInstance(users, str)
           self.assertEqual(users, '\n'.join((user,user2)))

    def test_write_then_create_list(self):
        test_str = 'some test string'
        with sphinx.connect() as s:
           self.assertTrue(sphinx.write(s, '\n'.join((pwd, test_str)).encode(), user, host))
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, size), str)
        with sphinx.connect() as s:
           users = sphinx.users(s, host)
           self.assertIsInstance(users, str)
           self.assertEqual(users, user)

    def test_create_then_write_list(self):
        test_str = 'some test string'
        with sphinx.connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, size), str)
        with sphinx.connect() as s:
           self.assertTrue(sphinx.write(s, '\n'.join((pwd, test_str)).encode(), user, host))
        with sphinx.connect() as s:
           users = sphinx.users(s, host)
           self.assertIsInstance(users, str)
           self.assertEqual(users, user)

    def test_read(self):
        test_str = 'some test string'
        with sphinx.connect() as s:
            self.assertTrue(sphinx.write(s, '\n'.join((pwd, test_str)).encode(), user, host))

        with sphinx.connect() as s:
            blob = sphinx.read(s, pwd.encode(), user, host)
        self.assertIsInstance(blob, str)
        self.assertEqual(blob, test_str)

    def test_overwrite(self):
        test_str0 = 'some test string'
        with sphinx.connect() as s:
            self.assertTrue(sphinx.write(s, '\n'.join((pwd, test_str0)).encode(), user, host))

        with sphinx.connect() as s:
            blob = sphinx.read(s, pwd.encode(), user, host)
        self.assertIsInstance(blob, str)
        self.assertEqual(blob, test_str0)

        test_str1 = 'another test string'
        with sphinx.connect() as s:
            self.assertTrue(sphinx.write(s, '\n'.join((pwd, test_str1)).encode(), user, host))

        with sphinx.connect() as s:
            blob = sphinx.read(s, pwd.encode(), user, host)
        self.assertIsInstance(blob, str)
        self.assertEqual(blob, test_str1)

    def test_double_commit(self):
        # create
        with sphinx.connect() as s:
            pwd0 = sphinx.create(s, pwd, user, host, char_classes, size)
            self.assertIsInstance(pwd0, str)

        # change
        with sphinx.connect() as s:
            pwd2 = sphinx.change(s, pwd, user, host)
        self.assertIsInstance(pwd2, str)
        self.assertNotEqual(pwd0, pwd2)

        # commit
        with sphinx.connect() as s:
            pwd4 = sphinx.commit(s, pwd, user, host, )
        self.assertIsInstance(pwd4, str)
        self.assertEqual(pwd2, pwd4)

        # commit
        with sphinx.connect() as s:
            self.assertRaises(ValueError, sphinx.commit,s, pwd, user, host)

    def test_main_create(self):
        sys.stdin = Input()
        self.assertIsNone(sphinx.main(('sphinx.py', 'create', user, host, char_classes, size)))

    def test_main_get(self):
        sys.stdin = Input()
        self.assertIsNone(sphinx.main(('sphinx.py', 'create', user, host, char_classes, size)))
        sys.stdin = Input()
        self.assertIsNone(sphinx.main(('sphinx.py', 'get', user, host)))

    def test_main_delete(self):
        sys.stdin = Input()
        self.assertIsNone(sphinx.main(('sphinx.py', 'create', user, host, char_classes, size)))
        sys.stdin = Input()
        self.assertIsNone(sphinx.main(('sphinx.py', 'delete', user, host)))

    def test_main_change_commit_undo(self):
        sys.stdin = Input()
        self.assertIsNone(sphinx.main(('sphinx.py', 'create', user, host, char_classes, size)))
        sys.stdin = Input()
        self.assertIsNone(sphinx.main(('sphinx.py', 'change', user, host)))
        sys.stdin = Input()
        self.assertIsNone(sphinx.main(('sphinx.py', 'commit', user, host)))
        sys.stdin = Input()
        self.assertIsNone(sphinx.main(('sphinx.py', 'undo', user, host)))

    def test_main_write_read(self):
        sys.stdin = Input("some note")
        self.assertIsNone(sphinx.main(('sphinx.py', 'write', user, host)))
        sys.stdin = Input()
        self.assertIsNone(sphinx.main(('sphinx.py', 'read', user, host)))
        sys.stdin = Input("some other note")
        self.assertIsNone(sphinx.main(('sphinx.py', 'write', host)))

    def test_main_inv_params(self):
        for cmd in ('create','get','change','commit','undo','delete','list','write','read'):
            self.assertRaises(SystemExit, sphinx.main, ('sphinx.py', cmd))

if __name__ == '__main__':
    unittest.main()
