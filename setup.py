#!/usr/bin/env python

# SPDX-FileCopyrightText: 2018, Marsiske Stefan 
# SPDX-License-Identifier: GPL-3.0-or-later

import os
#from distutils.core import setup, Extension
from setuptools import Extension, setup


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

from setuptools.command.sdist import sdist as SetuptoolsSdist
class BuildMakefilesSdist(SetuptoolsSdist):
    def run(self):
        os.chdir('man')
        os.system('make')
        os.chdir('..')
        SetuptoolsSdist.run(self)
from setuptools.command.build import build as SetuptoolsBuild
class BuildMakefilesBuild(SetuptoolsBuild):
    def run(self):
        os.chdir('man')
        os.system('make')
        os.chdir('..')
        SetuptoolsBuild.run(self)

import distutils.ccompiler
def spawn(self, cmd, **kwargs):
    filename = 'equihash'
    if self.compiler_type == "unix":
        # filenames are closer to the end of command line
        for argument in reversed(cmd):
            # Check if argument contains a filename. We must check for all
            # possible extensions; checking for target extension is faster.
            if not argument.endswith(self.obj_extension):
                continue

            # check for a filename only to avoid building a new string
            # with variable extension
            off_end = -len(self.obj_extension)
            off_start = -len(filename) + off_end
            if argument.endswith(filename, off_start, off_end):
                if self.compiler_type == 'bcpp':
                    # Borland accepts a source file name at the end,
                    # insert the options before it
                    cmd[-1:-1] = ("-std=c++17",)
                else:
                    cmd += ("-std=c++17",)

                # we're done, restore the original method
                #self.spawn = self.__spawn

            # filename is found, no need to search any further
            break
        else:
            if self.compiler_type == 'bcpp':
                # Borland accepts a source file name at the end,
                # insert the options before it
                cmd[-1:-1] = ("-std=c11",
                              "-Werror=implicit-function-declaration",)
            else:
                cmd += ("-std=c11",
                        "-Werror=implicit-function-declaration",)

    distutils.ccompiler.spawn(cmd, dry_run=self.dry_run, **kwargs)

distutils.ccompiler.CCompiler.__spawn = distutils.ccompiler.CCompiler.spawn
distutils.ccompiler.CCompiler.spawn = spawn

setup(name = 'pwdsphinx',
       version = '2.0.0',
       description = 'SPHINX password protocol',
       license = "GPLv3",
       author = 'Stefan Marsiske',
       author_email = 'sphinx@ctrlc.hu',
       url = 'https://github.com/stef/pwdsphinx',
       long_description=read('README.md'),
       long_description_content_type="text/markdown",
       packages = ['pwdsphinx'],
       install_requires = ("pysodium", "SecureString",
                           "qrcodegen","zxcvbn-python", 'pyequihash', 'pyoprf'),
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
       cmdclass={'sdist': BuildMakefilesSdist,
                 'build': BuildMakefilesBuild},
       ext_modules=[
           Extension(
               name="pwdsphinx._lib",  # as it would be imported
               sources=[
                   "deps/liboprf/src/dkg.c",
                   "deps/liboprf/src/oprf.c",
                   "deps/liboprf/src/toprf.c",
                   "deps/liboprf/src/utils.c",
                   "deps/liboprf/src/noise_xk/src/Noise_XK.c",
                   "deps/liboprf/src/noise_xk/src/XK.c",
                   "deps/equihash/equihash.cc"
               ],
               include_dirs=[
                   "deps/liboprf/src/",
                   "deps/liboprf/src/noise_xk/include",
                   "deps/liboprf/src/noise_xk/include/karmel/",
                   "deps/liboprf/src/noise_xk/include/karmel/minimal/",
                   "deps/equihash/",
                   "/opt/homebrew/include",
                   "/usr/local/include"
               ],
               library_dirs=[
                   "/opt/homebrew/lib",
                   "/usr/local/lib"
               ],
               extra_compile_args=[
                   "-O2",
                   "-Wall",
                   "-Werror",
                   "-Werror=format-security",
                   "-Wextra",
                   "-Wl,-z,defs",
                   "-Wl,-z,noexecstack",
                   "-Wl,-z,relro",
                   "-Wno-infinite-recursion",
                   "-Wno-unknown-warning-option",
                   "-Wno-unused-but-set-variable",
                   "-Wno-unused-parameter",
                   "-Wno-unused-variable",
                   "-Wno-unused-command-line-argument",
                   "-Wno-unreachable-code",
                   "-fasynchronous-unwind-tables",
                   #"-fcf-protection=full",
                   "-fpic",
                   "-fstack-clash-protection",
                   "-fstack-protector-strong",
                   #"-fstrict-flex-arrays=3",
                   "-fwrapv",
                   "-g",
                   #"-mbranch-protection=standard",
                   #"-march=native",
                   #"-std=c11",
                   #"-std=c++17",
                   ],
               libraries=["sodium"],
               define_macros=[("_BSD_SOURCE", None),
                              ("_DEFAULT_SOURCE", None),
                              ("WITH_SODIUM", None),
                              ("_GLIBCXX_ASSERTIONS", None),
                              ("_FORTIFY_SOURCE=2", None),
                              ],
        ),
    ]
)
