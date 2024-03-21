#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2023, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import os, tomllib
from pwdsphinx.utils import split_by_n

def getcfg(name):
  paths=[
      # read global cfg
      f'/etc/{name}/config',
      # update with per-user configs
      os.path.expanduser(f"~/.{name}rc"),
      # over-ride with local directory config
      os.path.expanduser(f"~/.config/{name}/config"),
      os.path.expanduser(f"{name}.cfg")
  ]
  config = dict()
  for path in paths:
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        continue
    except tomllib.TOMLDecodeError as ex:
        print(f"error in {path} at {ex}")
        continue
    config.update(data)
  return config


if __name__ == '__main__':
  import sys
  getcfg('sphinx').write(sys.stdout)
