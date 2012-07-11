#!/usr/bin/env python

class DATA_STREAM(object):
    def __init__(self,data):
        self.data = data
        self.bit_pos = 0
        self.byte_pos = 0

    def __len__(self):
        return len(self.data)*8-(self.byte_pos*8)-self.bit_pos

    def get_bits(self,nb):
        current_byte = ord(self.data[self.byte_pos])
        if nb < 8-self.bit_pos:
            r = (current_byte>>(8-self.bit_pos-nb)) & ~(0xffff<<nb)
        else:
            r = current_byte & ~(0xffff<<(8-self.bit_pos))
            bits_needed = nb - (8-self.bit_pos)
            cpt = 1
            while bits_needed > 7:
                r <<= 8
                r |= ord(self.data[self.byte_pos+cpt])
                bits_needed -= 8
                cpt += 1
            #print bits_needed
            #print  ord(self.data[self.byte_pos+cpt])>>(8-bits_needed)
            r = ~(0xffff<<bits_needed) & (ord(self.data[self.byte_pos+cpt])>>(8-bits_needed)) | (r<<bits_needed)
        self.byte_pos += ((self.bit_pos+nb)>>3) & 0x1fff
        self.bit_pos = (self.bit_pos+nb) & 0x7

        #print "Byte:%r BITS:%r" % (self.byte_pos,self.bit_pos)

        return r
