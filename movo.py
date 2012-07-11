#!/usr/bin/env python

import sys

def ROL(x,y):
    return ((x << y) | (x >> (16-y)))&0xffff

def ROR(x,y):
    return ((x>>y) | (x<<(16-y))) & 0xffff

addr = int(sys.argv[1],16)
reg = int(sys.argv[2],16)
val_obf = int(sys.argv[3],16)
val = int(sys.argv[4],16)

r5 = ((((val_obf<<6) + val_obf)<<4)+val_obf)&0xffff
r5 ^= 0x464d
r2 = addr ^ 0x6c38
r1 = reg + 2

r6 = 0
r8 = 0
while True:
    r7 = r6
    r5 = ROL(r5,1)
    r2 = ROR(r2,2)
    r2 += r5
    r2 &= 0xffff
    r5 += 2
    r5 &= 0xffff
    r6 = r2 ^ r5
    
    r8 = (r6 >> 8) & 0xff
    r6 &= 0xff
    r6 ^= r8
    r1 -= 1
    if r1 == 0:
        break

r6 <<= 8
r6 &= 0xffff
r6 |= r7
r2 = val
r2 ^= r6
print hex(r2)
