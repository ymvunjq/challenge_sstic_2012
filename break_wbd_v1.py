#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Bits import *
from WhiteDES import *
from DES import *
import sstic_value
from math import floor,log
from binascii import b2a_hex,a2b_hex
import sys,struct,random,pickle

def SubkeyToKey(sk,r=0):
    keys = []
    pc2 = [13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31]
    # These bits are not given by subkey, they have to be bruteforced
    missing_bits = [8,17,21,24,34,37,42,53]
    shifts = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
    s = sum(shifts[:r+1])
    
    CD = Bits(0,56)
    for i in xrange(len(pc2)):
        CD[pc2[i]] = sk[i].ival

    for i in xrange(256):
        k = Bits(CD.ival,56)
        v = Bits(i,8)
        for j in xrange(8):
            k[missing_bits[j]] = v[j].ival
        C = k[0:28]
        D = k[28:56]
        C = ((C << s) | (C >> (28-s)))
        D = ((D << s) | (D >> (28-s)))
        keys.append((C//D))

    return keys

def Sbox_one_round(R,fk,sbox):
    """ Represent one DES Round of SBOX """
    s = R ^ fk
    i = s[(5,0)].ival
    j = s[(4,3,2,1)].ival
    return Bits(S(sbox,j+(i<<4)),4)[::-1]
    
def Tbox_one_round(wt,M,r=0):
    t = 0
    S = Bits(0,96)
    # Expand à 96 bits
    ri,ro = 0,0
    for n in range(12):
        nt = t+8
        
        M[t:nt] = wt.KT[r][n][m[t:nt].ival]
        t = nt
    return wt.FX(m)
    # Expansion of data from 6 to 8 bits
    m = m // Bits(random.getrandbits(2),2)
    return wt.KT[0][0][m.ival]
    return wt.FX(m)

def SBOX(R,fk,log=False):
    """ Represent one DES Round of SBOX """
    s = R ^ fk
    ri,ro = (0,0)
    for n in xrange(8):
        (nri,nro) = (ri+6,ro+4)
        x = s[ri:nri]
        #if n == 1: print x.ival
        i = x[(5,0)].ival
        j = x[(4,3,2,1)].ival
        #Z[ro:nro] = Bits(S(n,j + (i << 4)),4)[::-1]
        print "SBOX%i = %r" % (n,Bits(S(n,j + (i << 4)),4)[::-1])
        (ri,ro) = (nri,nro)
    return Z

def Sbox_one_round2(R,fk,log=False):
    """ Represent one DES Round of SBOX """
    RE = E(R)
    Z = Bits(0,32)
    s = RE ^ fk
    ri,ro = (0,0)
    for n in xrange(8):
        (nri,nro) = (ri+6,ro+4)
        x = s[ri:nri]
        #if n == 1: print x.ival
        i = x[(5,0)].ival
        j = x[(4,3,2,1)].ival
        Z[ro:nro] = Bits(S(n,j + (i << 4)),4)[::-1]
        (ri,ro) = (nri,nro)
    return Z

def Tbox_one_round2(wt,M,r=0,log=False):
    blk = M[wt.tM1]
    t = 0
    for n in range(12):
        nt = t+8
        #if n == 0: print "T%s => %r %r  %r" % (str(n+1).ljust(2," "),m[t:nt-2].ival,str(m[t:nt]),str(Bits(wt.KT[r][n][m[t:nt].ival],8)))
        blk[t:nt] = wt.KT[r][n][blk[t:nt].ival]
        t = nt
    return wt.FX(blk)

def SboxOut2TboxOut(x):
    """ Return Tbox corresponding output bit of xe Sbox output bit """
    sbox = x/4
    return x%4+(sbox*8)

def go_to_tbox(x,tM2):
    y = SboxOut2TboxOut(x)
    print "SBOX output bit : %r => %r in TBOX" % (x,y)

    r = None
    for i in xrange(96):
        b = Bits(tM2[i])
        if b.size > y and b[y].ival == 1:
            return i/8
    return r

def bpkt(b,pkt=6):
    s = ""
    for i in xrange(0,b.size,pkt):
        s = s + "%s " % b[i:i+pkt]
    return s

def Einv(L):
    assert(L.size==48)

E_table = [31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0]

def generate_message(sbox,k):
    """ Génére un message à partir de m et faisant en sorte que le bit b sortant de la SBOX soit influencé par m """
    r = []
    bits = E_table[sbox*6:(sbox+1)*6]
    for i in xrange(64):
        R = Bits(random.getrandbits(32),32)
        for j in xrange(6):
            m = Bits(i,6)
            R[bits[j]] = m[j].ival
        r.append(R^k)
        
    return map(lambda x: Bits(0,32)//x,r)

def break_whiteDES_subkey(WT,sbox,subkeys=None):
    good = []

    # Taken from pdf
    bit = [2,6,10,14,17,23,27,29][sbox]

    # Récupération de la TBOX sur laquelle se dirigera le bit
    tbox = go_to_tbox(bit,WT.tM2)
    print "Tbox %r targeted with bit %r" % (tbox+1,bit)

    if subkeys is None: subkeys = range(64)

    # On teste toutes les sous-clés possibles (sous-clés de 6 bits 2^6 == 64)
    for sk in subkeys:
        sk = Bits(sk << sbox*6,32)
        i0 = []
        i1 = []
        i02 = []
        i12 = []
        # On teste des messages
        for M in generate_message(sbox,sk):
            r = Sbox_one_round2(M[32:64],sk)
    
            if r[bit].ival == 1:
                i1.append(IPinv(M))
            else:
                i0.append(IPinv(M))

        for e in i0:
            rw = Tbox_one_round2(WT,e)
            i02.append(rw[8*tbox:8*tbox+8].ival)
        for e in i1:
            rw = Tbox_one_round2(WT,e)
            i12.append(rw[8*tbox:8*tbox+8].ival)
            
        bad_key = False
        for e in i02:
            if e in i12:
                bad_key = True
                break
        if not bad_key:
            print "Good Key %r for sbox %r" % (sk.ival>>sbox*6,sbox+1)
            good.append(sk)
        else:
            #print "Bad Key %r for sbox %r" % (sk,sbox+1)
            pass
    

    if len(good) == 0:
        print "No good key found for sbox %r" % (sbox+1)

    return good

def break_whiteDES(WT,sk=None):
    if sk is None:
        sk = []
        for sbox in xrange(8):
            sk.append(break_whiteDES_subkey(WT,sbox))
        print sk

def return_master_key():
    sk = Bits(45,6)//Bits(6,6)//Bits(47,6)//Bits(43,6)//Bits(39,6)//Bits(46,6)//Bits(5,6)//Bits(57,6)
    pc1 = [56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3]
    keys = SubkeyToKey(sk)
    for k in xrange(len(keys)):
        k2 = Bits(0,64)
        k2[7] = 1
        k2[15] = 1
        k2[23] = 1
        k2[31] = 1
        k2[39] = 0
        k2[47] = 1
        k2[55] = 0
        k2[63] = 1        
        for i in xrange(len(pc1)):
            k2[pc1[i]] = keys[k][i].ival
        keys[k] = k2
    print "\n".join(map(lambda x:hex(x.ival)[2:-1],keys))
        
if __name__ == "__main__":
    soluce = [[45],[6],[47],[43],[39],[46],[5],[57]]
    WT = WhiteDES(sstic_value.KT,sstic_value.tM1,sstic_value.tM2,sstic_value.tM3)
    if len(sys.argv) == 2:
        break_whiteDES_subkey(WT,int(sys.argv[1])-1)
    elif len(sys.argv) > 2:
        break_whiteDES_subkey(WT,int(sys.argv[1])-1,map(int,sys.argv[2:]))
    else:
        return_master_key()
        sys.exit(0)
        key = break_whiteDES(WT)
        if key is None:
            print "Not Found !"
            sys.exit(1)
            print "KEY = %r" % key
