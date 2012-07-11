#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import struct
from Bits import Bits
from cpu import *


class UKN1(INSTRUCTION0op):
    def run(self):
        self.cpu.last_cmp.run()

class UKN2(INSTRUCTION0op):
    def run(self):
        print "***********************"

class CY16(CPU):
    opcodes = [
        OPCODE(MOV,0,"src","dst"),
        OPCODE(ADD,1,"src","dst"),
        OPCODE(ADDC,2,"src","dst"),
        OPCODE(SUB,3,"src","dst"),
        OPCODE(SUBB,4,"src","dst"),
        OPCODE(CMP,5,"src","dst"),
        OPCODE(AND,6,"src","dst"),
        OPCODE(TEST,7,"src","dst"),
        OPCODE(OR,8,"src","dst"),
        OPCODE(XOR,9,"src","dst"),
        OPCODE(JMP,12,"cond","offset"),
        OPCODE(CALL,10,"cond","vector"),
        OPCODE(SHR,104,"p1","dst"),
        OPCODE(SHL,105,"p1","dst"),
        OPCODE(ROR,106,"p1","dst"),
        OPCODE(ROL,107,"p1","dst"),
        OPCODE(ADDI,108,"p1","dst"),
        OPCODE(SUBI,109,"p1","dst"),
        OPCODE(NOT,888,"p1","dst"),
        OPCODE(STC,57282),
        OPCODE(CLC,57283),
        OPCODE(UKN1,57286),
        OPCODE(UKN2,57287),
        ]

    registers = [REGISTER("r%u"%i) for i in xrange(16)]

    def __init__(self):
        CPU.__init__(self)
        self.ram = RAM(self,0xd0000,word_size=2,endianness="LE")
        self.index = 0
        self.reading = True
        self.cmd = None
        self.last_cmp = None
        self.last_addr = None

    def usb_receive(self):
        r8 = self.registers[8].val
        addr = self.unpack(self.ram[r8+2])
        size = self.unpack(self.ram[r8+4])
        handle = self.unpack(self.ram[r8+6])
        self.pc = handle
        self.ram[addr] = self.ram_mips[self.index:self.index+size]

    def usb_sent(self):
        r8 = self.registers[8].val
        addr_buf = self.unpack(self.ram[r8+2:r8+4])
        handle = self.unpack(self.ram[r8+6])
        var_C = self.unpack(self.ram[addr_buf+0x10:addr_buf+0x12])
        o = self.unpack(self.ram[addr_buf+0x12:addr_buf+0x14])
        #print "VAR_C=%s O=%s" % (hex(var_C),hex(o))
        if (var_C & 0xfff0) != 0xfff0 and ((var_C&1)&0xff) != 0:
            self.ram_mips = self.ram_mips[0:var_C-1] + self.ram[addr_buf:addr_buf+16] + self.ram_mips[var_C+15:]
        if self.ram_mips[0x8000] != 0 and o == 0:
            print "##### STOP #####"
        self.index = o & 0xfffffff0
        if o&0xfff0 == 0xfff0:
            print "** SHOULD NOT SEND"
        self.pc = handle

    def usb_finish(self):
        stack = self.registers[15].val
        self.cmd = None
        if self.reading:
            self.ram[stack] = 0xae
            self.reading = False
        else:
            self.ram[stack] = 0x8a
            self.reading = True
            self.ram[0xc100] = "\x00\x00" + self.pack(self.registers[0].val&0xfff0,2) + "\x01\x00\x10\x00"
            self.registers[8].val = 0xc100

    def push(self,s):
        self.registers[15].val -= 2
        self.ram[self.registers[15].val] = s

    def pop(self):
        v = self.ram[self.registers[15].val:self.registers[15].val+2]
        self.registers[15].val += 2
        return self.unpack(v)

    def unpack(self,addr):
        if len(addr) == 1:
            return ord(addr)
        return struct.unpack("<H",addr)[0]

    def pack(self,v,size):
        if size == 1:
            return chr(v)
        else:
            return struct.pack("<H",v)

    def getopcode(self,data,addr):
        opcode = struct.unpack("<H",data[:2])[0]
        found = False
        for dec in (12,9,6,0):
            v = (opcode>>dec)
            if v in self.hopcodes:
                found = True
                break

        if not found:
            return UNKNOWN_INSTRUCTION(self,addr,data[:2]),data[2:]

        inst =  self.hopcodes[v].name(self,addr)
        data = inst.decode(data)
        return inst,data

    def is_set_flag(self,flag):
        cpu_flags = self.unpack(self.ram[0xc000])
        return cpu_flags&(1<<self._flags.index(flag)) != 0

    def addr_interpretation(self,addr,data):
        """ Dissect addr like src, dst
        Return 3 elements :
        - value of addr
        - type of action : 1 = byte, 2 = word
        - size in bytes of data consumed
        """
        address_type = addr>>4
        # Register Addressing : p59
        if address_type == 0:
            return ADDR(self,register=addr&0xf),2,0,None
        # Immediate Addressing : p59
        elif addr == 31:
            return self.unpack(data[0:2]),2,2,None
        # Indirect Addressing
        elif address_type == 1:
            if (addr>>3)&1 == 1:
                byte = 1
            else:
                byte = 2
            return ADDR(self,register=(addr&0b111)+8,at=True),byte,0,None
        # Direct Addressing
        elif address_type == 2 and (addr & 0x7) == 7:
            # Byte Access
            if (addr>>3)&1 == 1:
                byte = 1
            else:
                byte = 2
            return ADDR(self,addr=data[0:2]),byte,2,None
        # Indirect Addressing with Auto increment
        elif address_type == 2:
            if (addr>>3)&1 == 1:
                byte = 1
            else:
                byte = 2
            reg = (addr&0b111)+8
            inst = ADDI(self,p1=byte,dst=ADDR(self,register=reg))
            return ADDR(self,register=reg,at=True),byte,0,inst
        # Indirect adressing with Index
        elif address_type == 3:
            if (addr>>3)&1 == 1:
                byte = 1
            else:
                byte = 2
            reg = (addr&0x7)+8
            return ADDR(self,addr=data[0:2],register=reg,at=True),byte,2,None
        assert False,"OUIN"
