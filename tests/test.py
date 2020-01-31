import unittest
from os import listdir
from shutil import rmtree
from unittest.mock import Mock

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
host = 'example.com'


def cleanup():
    for f in listdir(data_dir):
        if f not in orig_data_files:
            rmtree(data_dir+f)


class TestEndToEnd(unittest.TestCase):

    def tearDown(self):
        cleanup()

    def test_create_user(self):
        with sphinx.connect() as s:
            self.assertTrue(sphinx.create(s, pwd, user, host, char_classes, size))

    def test_recreate_user(self):
        with sphinx.connect() as s:
            self.assertTrue(sphinx.create(s, pwd, user, host, char_classes, size))

        with sphinx.connect() as s:
            self.assertFalse(sphinx.create(s, pwd, user, host, char_classes, size))

    def test_get(self):
        with sphinx.connect() as s:
            self.assertTrue(sphinx.create(s, pwd, user, host, char_classes, size))

        with sphinx.connect() as s:
            self.assertTrue(sphinx.get(s, pwd, user, host))

    def test_delete(self):
        with sphinx.connect() as s:
            self.assertTrue(sphinx.create(s, pwd, user, host, char_classes, size))

        with sphinx.connect() as s:
            self.assertTrue(sphinx.delete(s, pwd, user, host))


if __name__ == '__main__':
    unittest.main()
