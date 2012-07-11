#!/usr/bin/env python
# -*- coding: utf-8 -*-

from math import floor,log
from binascii import b2a_hex,a2b_hex
import sys,struct,random,pickle
from Bits import *

class WhiteDES:
    def __init__(self, KT, tM1, tM2, tM3):
        self.KT = KT
        self.tM1 = tM1
        self.tM2 = tM2
        self.tM3 = tM3

    def FX(self, v):
        res = Bits(0, 96)
        for b in range(96):
            res[b] = ((v & self.tM2[b]).hw() % 2)
        return res

    def _cipher(self, M, d):
        assert (M.size == 64)
        if (d == 1):
            # Expand M from 64 to 96 bits
            blk = M[self.tM1]
            # Round number r
            for r in xrange(16):
                t = 0
                for n in xrange(12):
                    nt = (t + 8)
                    # blk[t:nt] => b0...7 represents the 8 input bits of each T-box
                    # KT contains 12 T-box (first 8 are non-linear, others are linear)
                    # 12 T-boxes are functionnaly equivalent to the round key addition, S-box operations, and the bypass of all 32 left bits and 32 right bits
                    blk[t:nt] = self.KT[r][n][blk[t:nt].ival]

                    t = nt

                blk = self.FX(blk)

            # Shrink blk from 96 to 64 bits
            # je pensais que M[self.tM1][self.tM3] == M, c'est presque le cas mais c'est pas ça
            return blk[self.tM3]
        if (d == -1):
            raise NotImplementedError

if __name__ == "__main__":
    import sstic_value
    wt = WhiteDES(sstic_value.KT,sstic_value.tM1,sstic_value.tM2,sstic_value.tM3)
    wt._cipher(Bits(int(sys.argv[1]),64),1)
