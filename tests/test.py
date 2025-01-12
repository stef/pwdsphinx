import unittest
from os import listdir, makedirs, environ, path
from shutil import rmtree, copyfile
from tempfile import mkdtemp
from unittest.mock import Mock
from io import BytesIO, StringIO
import sys, pysodium, subprocess, time, struct
import tracemalloc
from pyoprf import multiplexer
from pwdsphinx import sphinx, bin2pass, ostore, v1sphinx
from binascii import b2a_base64, a2b_base64
import pyoprf, ctypes
import contextlib

# to get coverage, run
# PYTHONPATH=.. coverage run ../tests/test.py
# coverage report -m
# to just run the tests do
# python3 -m unittest discover --start-directory ../tests

# disable the output of sphinx
sphinx.print = Mock()

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
ostore_server = environ.get('OPAQUESTORE_SERVER')
orig_servers=sphinx.servers
max_recovery_tokens = 2
ostore_max_fails = 3

class Input:
  def __init__(self, txt = None, pwd = pwd):
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
      cls._validate_password = sphinx.validate_password

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

      if ostore.available and ostore_server is not None and path.isfile(ostore_server):
        cls._ostore_root = mkdtemp(prefix='opaquestore-server-root.')
        root = cls._ostore_root
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
          with open(f"{root}/servers/{idx}/opaque-stored.cfg", 'w') as fd:
            fd.write(f'[server]\n'
                     f'verbose = true\n'
                     f'address = "127.0.0.1"\n'
                     f'port={23000+idx}\n'
                     f'timeout = 30\n'
                     f'max_kids = 5\n'
                     f'ssl_key= "key.pem"\n'
                     f'ssl_cert= "cert.pem"\n'
                     f'ltsigkey = "ltsig.key"\n'
                     f'record_salt = "some random string to salt the record ids"\n'
                     f'max_blob_size = 8192\n'
                     f'max_recovery_tokens = {max_recovery_tokens}\n'
                     f'max_fails = {ostore_max_fails}\n'
                     f'datadir = "data"\n\n')
        # lt sig pubkeys
        for idx in range(len(servers)):
          for pk, name in zip(pks, servers.keys()):
            with open(f"data/os_{name}.pub",'wb') as fd:
              fd.write(pk)
        for idx in range(len(servers)):
          log = open(f"{root}/servers/{idx}/log", "w")
          cls._oracles.append(
            (subprocess.Popen([ostore_server], cwd = f"{root}/servers/{idx}/", stdout=log, stderr=log, pass_fds=[log.fileno()]), log))
          log.close()
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
      sphinx.validate_password=self._validate_password
      time.sleep(0.1)
      sphinx.servers = orig_servers
      #cleanup()
      roots = [self._root]
      if hasattr(self, '_ostore_root'):
        roots.append(self._ostore_root)
      for idx in range(len(servers)):
        for root in roots:
          ddir = f"{root}/servers/{idx}/data/"
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

    def test_get_nonexistant_record(self):
        for i in [0, 1,2]:
          try: makedirs(f"{self._root}/servers/{i}/data/")
          except: pass
        with connect() as s:
            self.assertRaises(ValueError, sphinx.get, s, pwd, user, host)

    def test_get(self):
        with connect() as s:
            rwd0 = sphinx.create(s, pwd, user, host, char_classes, syms, size)
            self.assertIsInstance(rwd0, str)

        with connect() as s:
            rwd = sphinx.get(s, pwd, user, host)
        self.assertIsInstance(rwd, str)

        self.assertEqual(rwd,rwd0)

    def test_v1get(self):
        if not v1sphinx.enabled: return
        # synthetically create a v1 record
        id = v1sphinx.getid(host,user)
        for i in [1,2]:
          try: makedirs(f"{self._root}/servers/{i}/data/")
          except: pass
        ddir = f"{self._root}/servers/0/data/{id.hex()}"
        k = b'\x55' * 32
        #calculate rwd
        h0 = pysodium.crypto_generichash(pwd.encode(), outlen=pysodium.crypto_core_ristretto255_HASHBYTES);
        H0 = pysodium.crypto_core_ristretto255_from_hash(h0)
        H0_k = pysodium.crypto_scalarmult_ristretto255(k, H0)
        rwd0 = pysodium.crypto_generichash(pwd.encode()+H0_k, outlen=pysodium.crypto_core_ristretto255_BYTES);
        rwd0 = pysodium.crypto_pwhash(pysodium.crypto_core_ristretto255_BYTES,
                                      rwd0, id[:pysodium.crypto_pwhash_SALTBYTES],
                                      pysodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                      pysodium.crypto_pwhash_MEMLIMIT_INTERACTIVE)
        # create a rules blob
        if sphinx.validate_password:
            check_digit = pysodium.crypto_generichash(v1sphinx.CHECK_CTX, rwd0, 1)[0]
        else:
            check_digit = 0
        xor_mask = b'\x55' * 32
        packed = 30
        packed = packed + (sum(1<<i for i, c in enumerate(('u','l','d'))) << 7)
        packed = packed + (sum(1<<i for i, c in enumerate(bin2pass.symbols)) << (7 + 3))
        packed = packed + ((check_digit & ((1<<5) - 1)) << (7 + 3 + 33) )
        pt = packed.to_bytes(6,"big") + xor_mask
        rules = v1sphinx.encrypt_blob(pt)

        makedirs(ddir)
        with open(ddir+"/key", 'wb') as fd:
            fd.write(k)
        with open(ddir+"/pub", 'wb') as fd:
            sk, pk = v1sphinx.get_signkey(id, rwd0)
            fd.write(pk)
        with open(ddir+"/rules", 'wb') as fd:
            fd.write(rules)

        # create also a v1 users blob
        blobid=v1sphinx.getid(host,'')
        bddir = f"{self._root}/servers/0/data/{blobid.hex()}"
        makedirs(bddir)
        blob = user.encode()
        blob = v1sphinx.encrypt_blob(blob)
        blob = struct.pack("!H", len(blob)) + blob
        with open(bddir+"/pub", 'wb') as fd:
            sk, pk = v1sphinx.get_signkey(blobid, b'')
            fd.write(pk)
        with open(bddir+"/blob", 'wb') as fd:
            fd.write(blob)

        with connect() as s:
            rwd = sphinx.get(s, pwd, user, host)

        self.assertIsInstance(rwd, str)
        self.assertEqual(rwd,'_HO; <Yk)KA:G.q@8\\6zVHtDttCRA\\')

        self.assertTrue(not path.exists(ddir))
        self.assertTrue(not path.exists(bddir))
        # try to get the value now from the uplifted v2 record
        with connect() as s:
            rwd1 = sphinx.get(s, pwd, user, host)

        self.assertEqual(rwd,rwd1)

    def test_v1users(self):
        if not v1sphinx.enabled: return
        if sphinx.userlist == False: return

        with connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user, host, char_classes, syms, size), str)

        with connect() as s:
            self.assertIsInstance(sphinx.create(s, pwd, user2, host, char_classes, syms, size), str)

        with connect() as s:
            users = sphinx.users(s, host)
            self.assertIsInstance(users, str)
            self.assertEqual(users, '\n'.join((user,user2)))

        # synthetically create a v1 record
        id = v1sphinx.getid(host,'')
        for i in [1,2]:
          try: makedirs(f"{self._root}/servers/{i}/data/")
          except: pass
        ddir = f"{self._root}/servers/0/data/{id.hex()}"
        makedirs(ddir)

        v1users = {'v1user1', 'v1user2', 'v1used'}
        blob = ('\x00'.join(sorted(v1users))).encode()
        # notice we do not add rwd to encryption of user blobs
        blob = v1sphinx.encrypt_blob(blob)
        bsize = len(blob)
        blob = struct.pack("!H", bsize) + blob
        blob = v1sphinx.sign_blob(blob, id, b'')

        with open(ddir+"/pub", 'wb') as fd:
            sk, pk = v1sphinx.get_signkey(id, b'')
            fd.write(pk)
        with open(ddir+"/blob", 'wb') as fd:
            fd.write(blob)

        with connect() as s:
            users = sphinx.users(s, host)
            self.assertIsInstance(users, str)
            users = set(users.split('\n'))
            self.assertEqual(users, {'user1', 'user2'} | v1users)

    #def test_get_inv_mpwd(self):
    #    if not sphinx.validate_password:
    #        return
    #    with connect() as s:
    #        rwd0 = sphinx.create(s, pwd, user, host, char_classes, syms, size)
    #        self.assertIsInstance(rwd0, str)

    #    with connect() as s:
    #        self.assertRaises(ValueError, sphinx.get, s, 'zxcv1', user, host)

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

        if isinstance(self, TestEndToEndSingleMode):
          return
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

    def test_ostore_store(self):
      if not ostore.available or ostore_server is None: return
      sys.stdin = Input()
      self.assertIsNone(sphinx.main(('sphinx.py', 'store', user, 'opaque-store.cfg')))

    def test_ostore_read(self):
      if not ostore.available or ostore_server is None: return
      sys.stdin = Input()
      self.assertIsNone(sphinx.main(('sphinx.py', 'store', user, 'opaque-store.cfg')))

      sys.stdin = Input()
      f = StringIO()
      with contextlib.redirect_stdout(f):
        self.assertIsNone(sphinx.main(('sphinx.py', 'read', user)))
      with open('opaque-store.cfg','r') as fd:
        cfg = fd.read()
      self.assertTrue(cfg in f.getvalue())

    def test_ostore_read_invpwd(self):
      if not ostore.available or ostore_server is None: return
      vp = sphinx.validate_password
      sphinx.validate_password = False
      sys.stdin = Input()
      self.assertIsNone(sphinx.main(('sphinx.py', 'store', user, 'opaque-store.cfg')))

      sys.stdin = Input(pwd='qwer')
      self.assertRaises(ValueError, sphinx.main, ('sphinx.py', 'read', user))
      sphinx.validate_password = vp

    def test_ostore_replace(self):
      if not ostore.available or ostore_server is None: return
      sys.stdin = Input()
      self.assertIsNone(sphinx.main(('sphinx.py', 'store', user, 'opaque-store.cfg')))

      sys.stdin = Input()
      f = StringIO()
      with contextlib.redirect_stdout(f):
        self.assertIsNone(sphinx.main(('sphinx.py', 'read', user)))
      with open('opaque-store.cfg','r') as fd:
        cfg = fd.read()
      self.assertTrue(cfg in f.getvalue())

      sys.stdin = Input()
      self.assertIsNone(sphinx.main(('sphinx.py', 'replace', user, 'sphinx.cfg')))

      sys.stdin = Input()
      f = StringIO()
      with contextlib.redirect_stdout(f):
        self.assertIsNone(sphinx.main(('sphinx.py', 'read', user)))
      with open('sphinx.cfg','r') as fd:
        cfg = fd.read()
      self.assertTrue(cfg in f.getvalue())

    def test_ostore_replace_invpwd(self):
      if not ostore.available or ostore_server is None: return
      sys.stdin = Input()
      self.assertIsNone(sphinx.main(('sphinx.py', 'store', user, 'opaque-store.cfg')))

      sys.stdin = Input()
      f = StringIO()
      with contextlib.redirect_stdout(f):
        self.assertIsNone(sphinx.main(('sphinx.py', 'read', user)))
      with open('opaque-store.cfg','r') as fd:
        cfg = fd.read()
      self.assertTrue(cfg in f.getvalue())

      vp = sphinx.validate_password
      sphinx.validate_password = False

      sys.stdin = Input(pwd='qwer')
      self.assertRaises(ValueError, sphinx.main, ('sphinx.py', 'replace', user, 'sphinx.cfg'))

      sys.stdin = Input()
      f = StringIO()
      with contextlib.redirect_stdout(f):
        self.assertIsNone(sphinx.main(('sphinx.py', 'read', user)))
      with open('opaque-store.cfg','r') as fd:
        cfg = fd.read()
      self.assertTrue(cfg in f.getvalue())

    def test_ostore_erase(self):
      if not ostore.available or ostore_server is None: return
      sys.stdin = Input()
      self.assertIsNone(sphinx.main(('sphinx.py', 'store', user, 'opaque-store.cfg')))

      sys.stdin = Input()
      f = StringIO()
      with contextlib.redirect_stdout(f):
        self.assertIsNone(sphinx.main(('sphinx.py', 'read', user)))
      with open('opaque-store.cfg','r') as fd:
        cfg = fd.read()
      self.assertTrue(cfg in f.getvalue())

      sys.stdin = Input()
      self.assertIsNone(sphinx.main(('sphinx.py', 'erase', user)))

      sys.stdin = Input()
      self.assertRaises(ValueError, sphinx.main, ('sphinx.py', 'read', user))

    def test_ostore_erase_invpwd(self):
      if not ostore.available or ostore_server is None: return
      sys.stdin = Input()
      self.assertIsNone(sphinx.main(('sphinx.py', 'store', user, 'opaque-store.cfg')))

      sys.stdin = Input()
      f = StringIO()
      with contextlib.redirect_stdout(f):
        self.assertIsNone(sphinx.main(('sphinx.py', 'read', user)))
      with open('opaque-store.cfg','r') as fd:
        cfg = fd.read()
      self.assertTrue(cfg in f.getvalue())

      vp = sphinx.validate_password
      sphinx.validate_password = False

      sys.stdin = Input(pwd='qwer')
      self.assertRaises(ValueError, sphinx.main, ('sphinx.py', 'erase', user))

      sys.stdin = Input()
      f = StringIO()
      with contextlib.redirect_stdout(f):
        self.assertIsNone(sphinx.main(('sphinx.py', 'read', user)))
      with open('opaque-store.cfg','r') as fd:
        cfg = fd.read()
      self.assertTrue(cfg in f.getvalue())

    def test_ostore_recoverytokens(self):
      if not ostore.available or ostore_server is None: return
      sys.stdin = Input()
      self.assertIsNone(sphinx.main(('sphinx.py', 'store', user, 'opaque-store.cfg')))

      tokens = {i: set() for i in range(len(ostore.client.config['servers']))}
      for _ in range(max_recovery_tokens * 3):
        sys.stdin = Input()
        f = StringIO()
        with contextlib.redirect_stdout(f):
          self.assertIsNone(sphinx.main(('sphinx.py', 'recovery-tokens', user)))
        lines = f.getvalue().split('\n')
        self.assertTrue(len(lines)==3)
        self.assertTrue(lines[0]=='Store the following recovery token, in case this record is locked')
        self.assertTrue(lines[2]=='')
        self.assertTrue(len(a2b_base64(lines[1])) == 16 * len(ostore.client.config['servers']))
        stoks = sphinx.split_by_n(a2b_base64(lines[1]), 16)
        for i in range(len(ostore.client.config['servers'])):
          if len(tokens)<max_recovery_tokens and stoks[i] not in tokens[i]:
            tokens[i].add(stoks[i])
          if (len(tokens[i])==max_recovery_tokens):
            self.assertTrue(stoks[i] in tokens[i])

    def test_ostore_recoverytokens_invpwd(self):
      if not ostore.available or ostore_server is None: return
      sys.stdin = Input()
      self.assertIsNone(sphinx.main(('sphinx.py', 'store', user, 'opaque-store.cfg')))

      vp = sphinx.validate_password
      sphinx.validate_password = False

      sys.stdin = Input(pwd="qwer")
      self.assertRaises(ValueError, sphinx.main, ('sphinx.py', 'recovery-tokens', user))

    def test_ostore_unlock(self):
      if not ostore.available or ostore_server is None: return
      sys.stdin = Input()
      f = StringIO()
      with contextlib.redirect_stdout(f):
        self.assertIsNone(sphinx.main(('sphinx.py', 'store', user, 'opaque-store.cfg')))
      lines = f.getvalue().split('\n')
      self.assertTrue(lines[0] == 'successfully created opaque store record. Store the following recovery token, in case this record is locked')
      token = lines[1]

      vp = sphinx.validate_password
      sphinx.validate_password = False

      for i in range(ostore_max_fails+1):
        sys.stdin = Input(pwd="qwer")
        self.assertRaises(ValueError, sphinx.main, ('sphinx.py', 'read', user))

      sys.stdin = Input()
      self.assertRaises(ValueError, sphinx.main, ('sphinx.py', 'read', user))

      sys.stdin = Input()
      f = StringIO()
      with contextlib.redirect_stdout(f):
        self.assertIsNone(sphinx.main(('sphinx.py', 'unlock', user, token)))
      with open('opaque-store.cfg','r') as fd:
        cfg = fd.read()
      self.assertTrue(cfg in f.getvalue())

    def test_ostore_changepwd(self):
      if not ostore.available or ostore_server is None: return
      sys.stdin = Input()
      self.assertIsNone(sphinx.main(('sphinx.py', 'store', user, 'opaque-store.cfg')))

      sys.stdin = Input(txt='qwer')
      self.assertIsNone(sphinx.main(('sphinx.py', 'changepwd', user)))

      sys.stdin = Input(pwd='qwer')
      f = StringIO()
      with contextlib.redirect_stdout(f):
        self.assertIsNone(sphinx.main(('sphinx.py', 'read', user)))
      with open('opaque-store.cfg','r') as fd:
        cfg = fd.read()
      self.assertTrue(cfg in f.getvalue())

      sys.stdin = Input()
      self.assertRaises(ValueError, sphinx.main, ('sphinx.py', 'read', user))

    def test_ostore_edit(self):
      if not ostore.available or ostore_server is None: return
      sys.stdin = Input()
      self.assertIsNone(sphinx.main(('sphinx.py', 'store', user, 'opaque-store.cfg')))

      sys.stdin = Input()
      environ['EDITOR']=path.dirname(path.abspath(__file__)) + '/editor.py'
      self.assertIsNone(sphinx.main(('sphinx.py', 'edit', user)))

      sys.stdin = Input()
      f = StringIO()
      with contextlib.redirect_stdout(f):
        self.assertIsNone(sphinx.main(('sphinx.py', 'read', user)))
      with open('opaque-store.cfg','r') as fd:
        sorted_cfg = '\n'.join(sorted(fd.read().split('\n')))
      self.assertTrue(sorted_cfg == f.getvalue()[:-1] )

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

