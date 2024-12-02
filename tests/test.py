import unittest
from os import listdir, makedirs, environ, path
from shutil import rmtree, copyfile
from tempfile import mkdtemp
from unittest.mock import Mock
from io import BytesIO
import sys, pysodium, subprocess, time
import tracemalloc
from pyoprf import multiplexer
from pwdsphinx import sphinx, bin2pass
from binascii import b2a_base64
import pyoprf, ctypes

# to get coverage, run
# PYTHONPATH=.. coverage run ../tests/test.py
# coverage report -m
# to just run the tests do
# python3 -m unittest discover --start-directory ../tests

# disable the output of sphinx
#sphinx.print = Mock()

N = 3
data_dir = 'data/'
char_classes = 'uld'
syms = bin2pass.symbols
size = 0
pwd = 'asdf'
user = 'user1'
user2 = 'user2'
host = 'example.com'
servers = {'zero': {'host': 'localhost', 'port': 10000, 'ssl_cert': 'cert.pem'},
           'one':  {'host': 'localhost', 'port': 10001, 'ssl_cert': 'cert.pem'},
           'two':  {'host': 'localhost', 'port': 10002, 'ssl_cert': 'cert.pem'},
           'drei': {'host': 'localhost', 'port': 10003, 'ssl_cert': 'cert.pem'},
           'eris': {'host': 'localhost', 'port': 10004, 'ssl_cert': 'cert.pem'}
           }
corrupt_dkg_lib = environ.get('CORRUPT_DKG_LIB')
orig_servers=sphinx.servers

class Input:
  def __init__(self, txt = None):
    if txt:
      self.buffer = BytesIO('\n'.join((pwd, txt)).encode())
    else:
      self.buffer = BytesIO(pwd.encode())
  def isatty(self):
      return False
  def close(self):
    return

def connect(peers=None):
  if peers == None:
    peers = dict(tuple(servers.items())[:N])
  m = multiplexer.Multiplexer(peers)
  m.connect()
  return m

def bad_signkey(_, __):
  pk, sk = pysodium.crypto_sign_seed_keypair(b'\xfe'*pysodium.crypto_sign_SEEDBYTES)
  return sk, pk
get_signkey = sphinx.get_signkey

class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
      #libc = ctypes.cdll.LoadLibrary('libc.so.6')
      #cstderr = ctypes.c_void_p.in_dll(libc, 'stderr')
      #log_file = ctypes.c_void_p.in_dll(pyoprf.liboprf,'log_file')
      #log_file.value = cstderr.value

      cls._root = mkdtemp(prefix='sphinx-oracle-root.')
      root = cls._root
      pks = []
      for idx in range(len(servers)):
        makedirs(f"{root}/servers/{idx}")
        copyfile("cert.pem", f"{root}/servers/{idx}/cert.pem")
        copyfile("key.pem", f"{root}/servers/{idx}/key.pem")
        pk, sk = pysodium.crypto_sign_keypair()
        with open(f"{root}/servers/{idx}/ltsig.key", 'wb') as fd:
          fd.write(sk)
        #pks.append(b2a_base64(pk).decode("utf8")[:-1])
        pks.append(pk)
        with open(f"{root}/servers/{idx}/sphinx.cfg", 'w') as fd:
          fd.write(f'[server]\n'
                   f'verbose = true\n'
                   f'address = "127.0.0.1"\n'
                   f'port={10000+idx}\n'
                   f'timeout = 30\n'
                   f'max_kids = 5\n'
                   f'ssl_key= "key.pem"\n'
                   f'ssl_cert= "cert.pem"\n'
                   f'ltsigkey = "ltsig.key"\n'
                   f'datadir = "data"\n'
                   f'rl_decay=1800\n'
                   f'rl_threshold=10\n')
      # lt sig pubkeys
      for idx in range(len(servers)):
        for pk, name in zip(pks, servers.keys()):
          with open(f"data/{name}.pub",'wb') as fd:
            fd.write(pk)
      cls._oracles = []
      env = environ
      for idx in range(len(servers)):
        log = open(f"{root}/servers/{idx}/log", "w")
        if idx == N and corrupt_dkg_lib is not None:
          print(f"enabling byzantine peers {corrupt_dkg_lib}", file=log)
          env["BYZANTINE_DKG"]=corrupt_dkg_lib
        cls._oracles.append(
          (subprocess.Popen(["python3", path.dirname(path.abspath(sphinx.__file__)) + "/oracle.py"], cwd = f"{root}/servers/{idx}/", stdout=log, stderr=log, pass_fds=[log.fileno()], env=env), log))
        log.close()
      if corrupt_dkg_lib is not None:
        del env["BYZANTINE_DKG"]
      time.sleep(0.8)

    @classmethod
    def tearDownClass(cls):
      for p, log in cls._oracles:
        p.kill()
        r = p.wait()
        log.close()
      #rmtree(cls._root)
      time.sleep(0.4)

    def tearDown(self):
      sphinx.servers = orig_servers
      #cleanup()
      for idx in range(len(servers)):
        ddir = f"{self._root}/servers/{idx}/data/"
        if not path.exists(ddir): continue
        for f in listdir(ddir):
          if f == 'key': continue
          rmtree(ddir+f)

    def test_create_user(self):
        with connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, syms, size), str)

    def test_huge_user(self):
        if sphinx.userlist == False: return
        with connect() as s:
            self.assertRaises(ValueError, sphinx.create,s, pwd, 'a'*(2**16 - 40), host, char_classes, syms, size)
        with connect() as s:
            rwd=sphinx.create(s, pwd, 'a'*(2**16 - 42), host, char_classes, syms, size)
            self.assertIsInstance(rwd, str)
        with connect() as s:
            self.assertRaises(ValueError, sphinx.create, s, pwd, 'a', host, char_classes, syms, size)

    def test_rules_u(self):
        with connect() as s:
            rwd = sphinx.create(s, pwd, user, host, "u", '', 0)
        self.assertIsInstance(rwd, str)
        self.assertTrue(rwd.isupper())

    def test_rules_l(self):
        with connect() as s:
            rwd = sphinx.create(s, pwd, user, host, "l", '', 0)
        self.assertIsInstance(rwd, str)
        self.assertTrue(rwd.islower())

    def test_rules_d(self):
        with connect() as s:
            rwd = sphinx.create(s, pwd, user, host, "d", '', 0)
        self.assertIsInstance(rwd, str)
        self.assertTrue(rwd.isdigit())

    def test_rules_ulsd(self):
        with connect() as s:
            rwd = sphinx.create(s, pwd, user, host, char_classes, syms, 0)
        self.assertIsInstance(rwd, str)
        self.assertTrue(len(set([x.decode('utf8') for x in bin2pass.sets['u']]).intersection(rwd)) > 0)
        self.assertTrue(len(set([x.decode('utf8') for x in bin2pass.sets['l']]).intersection(rwd)) > 0)
        self.assertTrue(len(set([x.decode('utf8') for x in bin2pass.sets['d']]).intersection(rwd)) > 0)
        self.assertTrue(len(set(bin2pass.symbols).intersection(rwd)) > 0)

    def test_pwd_len(self):
        for i in range(1,32):
            with connect() as s:
                rwd = sphinx.create(s, pwd, user, host, char_classes, syms, i)
                self.assertIsInstance(rwd, str)
                self.assertTrue(len(rwd)==i)
            with connect() as s:
                self.assertTrue(sphinx.delete(s, pwd, user, host))

    def test_invalid_rules(self):
        with connect() as s:
            self.assertRaises(ValueError, sphinx.create, s, pwd, user, host, "asdf", syms, size)

    def test_recreate_user(self):
        with connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, syms, size), str)

        with connect() as s:
            self.assertRaises(ValueError, sphinx.create,s, pwd, user, host, char_classes, syms, size)
            s.close()

    def test_get(self):
        with connect() as s:
            rwd0 = sphinx.create(s, pwd, user, host, char_classes, syms, size)
            self.assertIsInstance(rwd0, str)

        with connect() as s:
            rwd = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(rwd, str)

        self.assertEqual(rwd,rwd0)

    def test_get_inv_mpwd(self):
        if not sphinx.validate_password:
            return
        with connect() as s:
            rwd0 = sphinx.create(s, pwd, user, host, char_classes, syms, size)
            self.assertIsInstance(rwd0, str)

        with connect() as s:
            self.assertRaises(ValueError, sphinx.get, s, 'zxcv1', user, host)

    def test_get_nonexistant_host(self):
        with connect() as s:
            self.assertRaises(ValueError, sphinx.get, s, pwd, user, host)

    def test_delete(self):
        with connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, syms, size), str)

        with connect() as s:
            self.assertTrue(sphinx.delete(s, pwd, user, host))

    def test_delete_inv_mpwd(self):
        if sphinx.rwd_keys == False: return
        with connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, syms, size), str)

        with connect() as s:
            self.assertRaises(ValueError, sphinx.delete, s, 'zxcv', user, host)

    def test_change(self):
        with connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, syms, size), str)

        with connect() as s:
            pwd0 = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(pwd0, str)

        with connect() as s:
            pwd1 = sphinx.change(s, pwd, pwd, user, host)
        self.assertIsInstance(pwd1, str)
        self.assertNotEqual(pwd0, pwd1)

        with connect() as s:
            pwd2 = sphinx.change(s, pwd, pwd.upper(), user, host)
        self.assertIsInstance(pwd2, str)
        self.assertNotEqual(pwd0, pwd2)
        self.assertNotEqual(pwd1, pwd2)

    def test_commit_undo(self):
        # create
        with connect() as s:
            pwd0 = sphinx.create(s, pwd, user, host, char_classes, syms, size)
        self.assertIsInstance(pwd0, str)

        # get
        with connect() as s:
            pwd1 = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(pwd1, str)
        self.assertEqual(pwd0, pwd1)

        # change
        with connect() as s:
            pwd2 = sphinx.change(s, pwd, pwd.upper(), user, host)
        self.assertIsInstance(pwd2, str)
        self.assertNotEqual(pwd1, pwd2)

        # get
        with connect() as s:
            pwd3 = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(pwd3, str)
        self.assertEqual(pwd1, pwd3)

        # commit
        with connect() as s:
            sphinx.commit(s, pwd, user, host)
        with connect() as s:
            pwd4 = sphinx.get(s, pwd.upper(), user, host)
        self.assertIsInstance(pwd4, str)
        self.assertEqual(pwd2, pwd4)

        # undo
        with connect() as s:
            sphinx.undo(s, pwd.upper(), user, host, )
        with connect() as s:
            pwd5 = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(pwd5, str)
        self.assertEqual(pwd1, pwd5)

    def test_commit_undo_inv_mpwd(self):
        # create
        if sphinx.rwd_keys == False: return
        with connect() as s:
            pwd0 = sphinx.create(s, pwd, user, host, char_classes, syms, size)
            self.assertIsInstance(pwd0, str)

        # change invalid mpwd
        with connect() as s:
           self.assertRaises(ValueError, sphinx.change,s, 'zxcv', pwd, user, host)

        # change correct mpwd
        with connect() as s:
           pwd2 = sphinx.change(s, pwd, pwd, user, host)
        self.assertIsInstance(pwd2, str)
        self.assertNotEqual(pwd0, pwd2)

        # commit invalid mpwd
        with connect() as s:
           self.assertRaises(ValueError, sphinx.commit,s, 'zxcv', user, host)

        # commit correct mpwd
        with connect() as s:
           sphinx.commit(s, pwd, user, host)
        with connect() as s:
           pwd4 = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(pwd4, str)
        self.assertEqual(pwd2, pwd4)

        # undo invalid mpwd
        with connect() as s:
           self.assertRaises(ValueError, sphinx.undo,s, 'zxcv', user, host)

        # undo correct mpwd
        with connect() as s:
           sphinx.undo(s, pwd, user, host)
        with connect() as s:
           pwd5 = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(pwd5, str)
        self.assertEqual(pwd0, pwd5)

    def test_list_users(self):
        if sphinx.userlist == False: return
        with connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, syms, size), str)
        with connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user2, host, char_classes, syms, size), str)
        with connect() as s:
            users = sphinx.users(s, host)
            self.assertIsInstance(users, str)
            self.assertEqual(users, '\n'.join((user,user2)))

    def test_list_users_diff_mpwd(self):
        if sphinx.userlist == False: return
        with connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, syms, size), str)
        with connect() as s:
            self.assertIsInstance(sphinx.create(s, 'zxcv', user2, host, char_classes, syms, size), str)
        with connect() as s:
            users = sphinx.users(s, host)
            self.assertIsInstance(users, str)
            self.assertEqual(users, '\n'.join((user,user2)))

    def test_double_commit(self):
        # create
        with connect() as s:
            pwd0 = sphinx.create(s, pwd, user, host, char_classes, syms, size)
            self.assertIsInstance(pwd0, str)

        # change
        with connect() as s:
            pwd2 = sphinx.change(s, pwd, pwd, user, host)
        self.assertIsInstance(pwd2, str)
        self.assertNotEqual(pwd0, pwd2)

        # commit
        with connect() as s:
            sphinx.commit(s, pwd, user, host)
        with connect() as s:
            pwd4 = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(pwd4, str)
        self.assertEqual(pwd2, pwd4)

        # commit
        with connect() as s:
            self.assertRaises(ValueError, sphinx.commit,s, pwd, user, host)

    def test_auth(self):
        # create
        with connect() as s:
            rwd = sphinx.create(s, pwd, user, host, char_classes, syms, size)
            self.assertIsInstance(rwd, str)
        sphinx.get_signkey = bad_signkey
        with connect() as s:
             self.assertRaises(ValueError, sphinx.change, s, pwd, pwd, user, host, char_classes, syms, size)
        sphinx.get_signkey = get_signkey

    def test_userblob_auth_create(self):
        if sphinx.userlist == False: return
        # create
        with connect() as s:
            rwd = sphinx.create(s, pwd, user, host, char_classes, syms, size)
            self.assertIsInstance(rwd, str)
        sphinx.get_signkey = bad_signkey
        with connect() as s:
            self.assertRaises(ValueError, sphinx.create, s, pwd, user2, host, char_classes, syms, size)
        sphinx.get_signkey = get_signkey

    def test_create_user_xormask(self):
        with connect() as s:
          rwd = sphinx.create(s, pwd, user, host, '', '', 0, pwd)
        self.assertIsInstance(rwd, str)
        self.assertEqual(pwd, rwd)

    def test_change_xormask(self):
        with connect() as s:
          rwd0 = sphinx.create(s, pwd, user, host, char_classes, syms, size)
          self.assertIsInstance(rwd0, str)

        with connect() as s:
            rwd1 = sphinx.change(s, pwd, pwd, user, host, '', '', 0, pwd)
        self.assertIsInstance(rwd1, str)
        self.assertEqual(rwd1, pwd)

        with connect() as s:
            rwd2 = sphinx.change(s, pwd, pwd, user, host, '', '', 0, pwd+pwd)
        self.assertIsInstance(rwd2, str)
        self.assertEqual(rwd2, pwd+pwd)

    def test_corrupted_dkg(self):
        sphinx.servers = {
          'zero': { 'host': "localhost",
                    'port': 10000,
                    'ssl_cert': "cert.pem",
                    'ltsigkey': "data/zero.pub"},
          'drei': { 'host': "localhost",
                    'port': 10003,
                    'ssl_cert': "cert.pem",
                    'ltsigkey': "data/drei.pub"},
          'eris': { 'host': "localhost",
                    'port': 10004,
                    'ssl_cert': "cert.pem",
                    'ltsigkey': "data/eris.pub"}
        }

        if corrupt_dkg_lib is None:
          # skipping since we don't have the byzantine peers lib
          return
        with connect(sphinx.servers) as s:
          self.assertRaises(ValueError, sphinx.create ,s, pwd, user, host, char_classes, syms, size)

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

    def test_predefined_pwd(self):
        with connect() as s:
            rwd0 = sphinx.create(s, pwd, user, host, char_classes, syms, size, target = pwd)
            self.assertIsInstance(rwd0, str)
        self.assertEqual(pwd,rwd0)

        with connect() as s:
            rwd = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(rwd, str)

        self.assertEqual(rwd,rwd0)

    def test_predefined_raw(self):
        target = b'A' * 32
        with connect() as s:
            rwd0 = sphinx.create(s, pwd, 'raw://'+user, host, '', '', 0, target = target)
        self.assertEqual(target,rwd0)

        with connect() as s:
            rwd = sphinx.get(s, pwd, 'raw://'+user, host)

        self.assertEqual(rwd,rwd0)

class TestEndToEndNoUserlist(TestEndToEnd):
  def setUp(self):
    if sphinx.userlist:
      sphinx.userlist=False
  def tearDown(self, *args, **kwargs):
    super(TestEndToEndNoUserlist, self).tearDown(*args, **kwargs)
    sphinx.userlist=True

class TestEndToEndNoRWD_Keys(TestEndToEnd):
  def setUp(self):
    if sphinx.rwd_keys:
      sphinx.rwd_keys=False
  def tearDown(self, *args, **kwargs):
    super(TestEndToEndNoRWD_Keys, self).tearDown(*args, **kwargs)
    sphinx.rwd_keys=True

class TestEndToEndNoValidatePassword(TestEndToEnd):
  def setUp(self):
    if sphinx.validate_password:
      sphinx.validate_password=False
  def tearDown(self, *args, **kwargs):
    super(TestEndToEndNoValidatePassword, self).tearDown(*args, **kwargs)
    sphinx.validate_password=True

class TestEndToEndNoneEither(TestEndToEnd):
  def setUp(self):
    if sphinx.validate_password:
      sphinx.validate_password=False
    if sphinx.rwd_keys:
      sphinx.rwd_keys=False
    if sphinx.userlist:
      sphinx.userlist=False
  def tearDown(self, *args, **kwargs):
    super(TestEndToEndNoneEither, self).tearDown(*args, **kwargs)
    sphinx.validate_password=True
    sphinx.rwd_keys=True
    sphinx.userlist=True

class TestEndToEndSingleMode(TestEndToEnd):
  def setUp(self):
    self.threshold=sphinx.threshold
    sphinx.threshold=1
    sphinx.servers=dict(list(sphinx.servers.items())[:1])
    global N
    self.N=N
    N=1

  def tearDown(self, *args, **kwargs):
    super(TestEndToEndSingleMode, self).tearDown(*args, **kwargs)
    sphinx.servers=orig_servers
    sphinx.threshold=self.threshold
    global N
    N=self.N

if __name__ == '__main__':
  unittest.main()

