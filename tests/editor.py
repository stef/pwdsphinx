#!/usr/bin/env python

import sys

with open(sys.argv[1], 'r') as fd:
    data = fd.read()

with open(sys.argv[1], 'w') as fd:
    fd.write('\n'.join(sorted(data.split('\n'))))
