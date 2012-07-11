#!/usr/bin/env python
# -*- coding: utf-8 -*-

from math import floor,log
from binascii import b2a_hex,a2b_hex
import sys,struct,random,pickle

class Bits:
    def __init__(self,v,size=None):
        self.ival = 0
        self.size = 1
        self.mask = 1
        if isinstance(v,Bits):
            self.ival = v.ival
            self.size = v.size
            self.mask = v.mask
        elif isinstance(v,int) or isinstance(v,long):
            if v:
                self.ival = abs(v*1)
                self.size = int(floor(log(self.ival) / log(2) + 1))
                self.mask = (1 << self.size) - 1
        elif isinstance(v,list):
            self.size = len(v)
            self.mask = (1 << self.size) - 1
            for i,x in enumerate(v):
                self[i] = x
        elif isinstance(v,str):
            self.size = len(v)*8
            self.mask = (1 << self.size) - 1
            l = map(ord,v)
            i = 0
            for o in l:
                self[i:i+8] = Bits(o,8).bitlist()[::-1]
                i += 8

        if size:
            self.size = size
        

    def __len__(self):
        return self.size

    def bit(self,i):
        if i in range(self.size):
            return ((self.ival >> i) & 1L)
        else:
            i = -i
            if i in range(self.size+1):
                return ((self.ival >> (self.size+i)) & 1L)

        raise IndexError

    def __setattr__(self,field,v):
        if field == "size":
            self.__dict__["size"] = v
            self.__dict__["mask"] = (1 << v) - 1
        else:
            self.__dict__[field] = v

    def __repr__(self):
        c = self.__class__
        l = self.size
        s = self.ival
        return "<%s instance with ival=%x (len=%d)>" % (c,s,l)

    def __str__(self):
        """ binary string representation, bit0 first """
        s = ''
        for i in self:
            #print "I = %r %r" %(i,self.size)
            s = s + str(i)
        return s

    def __hex__(self):
        """ 'byte string representation, bit0 first. """
        s = "%x" % self[::-1].ival
        return a2b_hex(s.rjust(self.size/4,'0'))


    def __cmp__(self,a):
        if isinstance(a,Bits):
            if self.size != a.size:
                raise ValueError
            else:
                return cmp(self.ival,a.ival)
        else:
            raise AttributeError


    def __eq__(self,a):
        if isinstance(a,Bits): a = a.ival
        return self.ival == a
        

    def __ne__(self,a):
        if isinstance(a,Bits): a = a.ival
        return self.ival != a

    def __iter__(self):
        for x in range(self.size):
            yield self.bit(x)

    def __getitem__(self,i):
        if isinstance(i,int):
            return Bits(self.bit(i),1)
        elif isinstance(i,slice):
            return Bits(self.bitlist()[i])
        else:
            s = []
            for x in i:
                s.append(self.bit(x))
            return Bits(s)
                

    def __setitem__(self,i,v):
        """ setitem defines
        b[i]=v with v in (0,1),
        b[i:j]=v
        and b[list]=v where
        v is iterable with range equals to that required by i:j or list,
        or v generates a Bits instance of desired length.
        """
        if isinstance(i,int):
            if v in (0,1):
                if i in range(self.size):
                    if self.bit(i) == 1:
                        self.ival -= (1 << i)
                    self.ival += (v & 1) << i
                else:
                    i = -i
                    if i in range(self.size+1):
                        p = self.size + i
                        if self.bit(p) == 1:
                            self.ival -= 1 << p
                        self.ival += (v&1) << p
                    else:
                        raise IndexError
            else:
                raise AssertionError
        else:
            if isinstance(i,slice):
                (start,stop,step) = i.indices(self.size)
                r = range(start,stop,step)
            else:
                r = i
            try:
                if len(r) == len(v):
                    for j,b in zip(r,v):
                        self[j] = b
                else:
                    raise AssertionError
            except (TypeError,AssertionError):
                for j,b in zip(r,Bits(v,len(r))):
                    self[j] = b
                

    def __lshift__(self,i):
        res = Bits(self)
        res.ival = res.mask & (res.ival << i)
        return res

    def __rshift__(self,i):
        res = Bits(self)
        res.ival = res.mask & (res.ival >> i)
        return res

    def __invert__(self):
        res = Bits(self)
        res.ival = res.mask ^ res.ival
        return res

    def __and__(self,rvalue):
        if isinstance(rvalue,Bits):
            obj = rvalue
        else:
            obj = Bits(rvalue)
        if self.size > obj.size:
            res = Bits(self)
        else:
            res = Bits(obj)
        res.ival = self.ival & obj.ival
        return res

    def __or__(self,rvalue):
        if isinstance(rvalue,Bits):
            obj = rvalue
        else:
            obj = Bits(rvalue)
        if self.size > obj.size:
            res = Bits(self)
        else:
            res = Bits(obj)
        res.ival = self.ival | obj.ival
        return res

    def __xor__(self,rvalue):
        if isinstance(rvalue,Bits):
            obj = rvalue
        else:
            obj = Bits(rvalue)
        if self.size > obj.size:
            res = Bits(self)
        else:
            res = Bits(obj)
        res.ival = self.ival ^ obj.ival
        return res


    def __rand__(self,lvalue):
        return self & lvalue

    def __ror__(self,lvalue):
        return self | lvalue

    def __rxor__(self,lvalue):
        return self ^ lvalue

    def __floordiv__(self,rvalue):
        """ operator // is used for concatenation. """
        if isinstance(rvalue,Bits):
            obj = rvalue
        else:
            obj = Bits(rvalue)
        return Bits(self.bitlist() + obj.bitlist())

    def bitlist(self):
        return map(int,str(self))

    def hw(self):
        """ hamming weight of the object (count of 1s). """
        return self.bitlist().count(1)

    def hd(self,other):
        """ hamming distance to another object of same length. """
        if isinstance(other,Bits):
            obj = other
        else:
            obj = Bits(other)
        if self.size != obj.size:
            raise ValueError
        else:
            return (self ^ obj).hw()    
