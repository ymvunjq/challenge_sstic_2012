#!/usr/bin/env python

# Valid Key = fa8cfbd5

import struct,sys

if len(sys.argv) != 2:
    print ("Usage: %s hex_key" % sys.argv[0])
    sys.exit(1)

key = int(sys.argv[1],16)
layer1_str = open("layer2.bin","r").read()
layer_size = len(layer1_str)

def swap_word(word):
    w1 = word&0xff
    w2 = ((word&0xff00)>>8)&0xff
    return ((w1<<8)|w2)&0xffff

def swap_key(x):
    w1 = (x&0xffff)&0xffff
    w2 = ((x&0xffff0000)>>16)&0xffff
    w1 = swap_word(w1)
    w2 = swap_word(w2)
    return ((w2<<16)|w1)&0xffffffff

def unpack(s):
    return struct.unpack(">I",s)[0]

def pack(i):
    return struct.pack(">I",i)

key = swap_key(key)
count = 1
ptr = pack(key ^ unpack(layer1_str[:4]))
while True:
    if count >= (layer_size-2)/4:
        f=open("layer2_unencode.bin","wb")
        f.write(ptr)
        f.close()
        sys.exit(0)

    a0 = unpack(layer1_str[count*4:(count+1)*4])
    v0 = ((1 - count)*4)
    v0 = -v0
    v0 = unpack(ptr[v0:v0+4])
    ptr = ptr + pack(v0 ^ a0)
    count += 1
