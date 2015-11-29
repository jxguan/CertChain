#!/usr/bin/env python

import os
from glob import glob

print "Resetting nodes..."

try:
    os.remove('data_dir/hashchain.dat')
    os.remove('data_dirs/nodeA/hashchain.dat')
    os.remove('data_dirs/nodeB/hashchain.dat')
except:
    pass
print "Removed hashchains."

for f in glob('data_dirs/nodeA/documents/*'):
    os.remove(f)
for f in glob('data_dirs/nodeB/documents/*'):
    os.remove(f)
for f in glob('data_dir/documents/*'):
    os.remove(f)
print "Removed documents."

for f in glob('data_dirs/nodeA/replicas/*'):
    os.remove(f)
for f in glob('data_dirs/nodeB/replicas/*'):
    os.remove(f)
for f in glob('data_dir/replicas/*'):
    os.remove(f)
print "Removed replicas."
