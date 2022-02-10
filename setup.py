#!/usr/bin/env python

# SPDX-FileCopyrightText: 2018, Marsiske Stefan 
# SPDX-License-Identifier: GPL-3.0-or-later

import os
#from distutils.core import setup, Extension
from setuptools import setup


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name = 'pwdsphinx',
       version = '1.0.1',
       description = 'SPHINX password protocol',
       license = "GPLv3",
       author = 'Stefan Marsiske',
       author_email = 'sphinx@ctrlc.hu',
       url = 'https://github.com/stef/pwdsphinx',
       long_description=read('README.md'),
       long_description_content_type="text/markdown",
       packages = ['pwdsphinx'],
       install_requires = ("pysodium", "SecureString", "qrcodegen","zxcvbn-python", 'pyequihash'),
       classifiers = ["Development Status :: 4 - Beta",
                      "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
                      "Topic :: Security :: Cryptography",
                      "Topic :: Security",
                   ],
       entry_points = {
           'console_scripts': [
               'oracle = pwdsphinx.oracle:main',
               'sphinx = pwdsphinx.sphinx:main',
               'websphinx = pwdsphinx.websphinx:main',
               'bin2pass = pwdsphinx.bin2pass:main',
           ],
       },
       #ext_modules = [libsphinx],
)
