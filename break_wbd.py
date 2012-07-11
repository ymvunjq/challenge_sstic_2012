#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Bits import *
from WhiteDES import *
from DES import *
import sstic_value
import sys

def SBOX(R,fk,n,log=False):
    """ Représente une SBOX """
    s = R ^ fk
    x = s[0:6]
    i = x[(5,0)].ival
    j = x[(4,3,2,1)].ival
    #print "SBOX%i = %r" % (n,Bits(S(n,j + (i << 4)),4)[::-1])
    return Bits(S(n,j + (i << 4)),4)[::-1]


def break_sbox_key(wt,sbox):
    """ Casse la sous clé de la sbox correspondant à la WhiteBox wt """
    # Pour toute les clés possible
    for k in xrange(64):
        tbox = range(12)
        bad_key = False
        for m in xrange(64):
            M = Bits(m,6)
            res_sbox = SBOX(M,k,sbox)
            for i in xrange(4):
                M2 = M//Bits(i,2)
                good_tbox = []
                for ntbox in tbox:
                    res_tbox = wt.KT[0][ntbox][M2.ival]
                    if Bits(res_tbox,8)[0:4] == res_sbox:
                        good_tbox.append(ntbox)
                tbox = good_tbox
                if len(tbox) == 0:
                    bad_key = True
                    break
            if bad_key: break
        if not bad_key: return Bits(k,6)
    return None

def break_white_box(wt):
    """ Trouve la clé correspondant à la WhiteBOX wt """

    # On trouve toutes les sous-clés, soit 48 bits
    for i in xrange(8):
        if i == 0:
            sk = break_sbox_key(wt,i)
        else:
            sk = sk//break_sbox_key(wt,i)

    fixed_bits = range(7,64,8)
    pc1 = [56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3]
    pc2 = [13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31]
    M = Bits(random.getrandbits(64),64)
    # These bits are not given by subkey, they have to be bruteforced
    missing_bits = [8,17,21,24,34,37,42,53]
    shifts = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
    s = sum(shifts[:1])

    CD = Bits(0,56)
    for i in xrange(len(pc2)):
        CD[pc2[i]] = sk[i].ival

    # Brute force des 8 derniers bits
    for i in xrange(256):
        k = Bits(CD.ival,56)
        v = Bits(i,8)
        for j in xrange(8):
            k[missing_bits[j]] = v[j].ival
        C = k[0:28]
        D = k[28:56]
        C = ((C << s) | (C >> (28-s)))
        D = ((D << s) | (D >> (28-s)))
        k = C//D

        K = Bits(0,64)
        # Valeur fixe
        K[fixed_bits] = 175
        for j in xrange(len(pc1)):
            K[pc1[j]] = k[j].ival
        if WT._cipher(M,1) == enc(K,M):
            return K

def conv(x):
    """ Convertit la clé pour qu'elle soit correctement lue par a2b_hex """
    s = "".join(map(str,x.bitlist()))
    s2 = ""
    r = ""
    for i in xrange(8):
        s2 = s2 + chr(int(s[i*8:(i+1)*8],2))
    for c in s2:
        r=r+hex(ord(c))[2:].rjust(2,"0")
    return r

if __name__ == "__main__":
    WT = WhiteDES(sstic_value.KT,sstic_value.tM1,sstic_value.tM2,sstic_value.tM3)
    key = break_white_box(WT)
    print "WhiteBoxKey = " + conv(key)
