from os import mkdir, getenv
from os.path import exists, split
from pathlib import Path
from sys import executable

EXT_NM_TPL = '''{{
  "name": "websphinx",
  "description": "Host for communicating with PITCHFORKed Sphinx",
  "path": "{cmd}",
  "type": "stdio",
'''

CHR_NM_TPL = EXT_NM_TPL + '''  "allowed_origins": [
    "chrome-extension://ojbhlhidchjkmjmpeonendekpoacahni/"
  ]
}}
'''

FF_NM_TPL = EXT_NM_TPL + '''  "allowed_extensions": [
    "sphinx@ctrlc.hu"
  ]
}}
'''


def get_executable():
    venv = getenv('VIRTUAL_ENV')
    if venv:
        return f'{venv}/bin/websphinx'
    d = split(Path(__file__).absolute())[0]
    return d + '/websphinx.py'


def init_browser_ext():
    cmd = get_executable()
    print(cmd)
    # init ff
    if exists(f'{Path.home()}/.mozilla/'):
        nm_dir = f'{Path.home()}/.mozilla/native-messaging-hosts/'
        if not exists(nm_dir):
            mkdir(nm_dir)
        with open(nm_dir+'websphinx.json', 'w') as outfile:
            ff_nm = FF_NM_TPL.format(cmd=cmd)
            outfile.write(ff_nm)
    # init chrome
    if exists(f'{Path.home()}/.config/chromium'):
        nm_dir = f'{Path.home()}/.config/chromium/NativeMessagingHosts/'
        if not exists(nm_dir):
            mkdir(nm_dir)
        with open(nm_dir+'websphinx.json', 'w') as outfile:
            chr_nm = CHR_NM_TPL.format(cmd=cmd)
            outfile.write(chr_nm)
