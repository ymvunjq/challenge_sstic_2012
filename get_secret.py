#!/usr/bin/env python
# -*- coding: utf-8 -*-

# dd if=part skip=26625 of=secret1 bs=4096 count=12
# dd if=part skip=26638 of=secret2 bs=4096 count=245
# cat secret1 secret2 > secret
# ./bin/bf_secret.py secret
# Found with size 1048592


import sys,md5

def check_secret(s):
    return s[:16] == md5.md5(s[16:]).digest()

def f2s(p):
    f=open(p,'rb')
    s=f.read()
    f.close()
    return s

def s2f(s,p):
    f=open(p,'wb')
    f.write(s)
    f.close()

secret = f2s(sys.argv[1])
size_file = len(secret)

for i in reversed(xrange(17,size_file)):
    if check_secret(secret[:i]):
        print "Found withe size %u" % i
        s2f(secret[:i],"secret.bin")
        sys.exit(0)

print "Not found"
sys.exit(1)
