#!/usr/bin/env python3

from pwdsphinx import websphinx
websphinx.create({'cmd': 'create', 'site': 'www.example.com', 'name': 'joe', 'rules': 'ulsd', 'size': 0, 'mode': 'test'})
