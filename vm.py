#!/usr/bin/env python

from cpu import *
from stream import DATA_STREAM


class ADDR_VM(ADDR):
    def __init__(self,cpu,addr=None,register=None,at=False,obf=None):
        ADDR.__init__(self,cpu,addr,register,at)
        self.obf = obf

    def __str__(self):
        return ADDR.__str__(self) + "{%s}" % hex(self.obf)

class INSTRUCTION_VM(INSTRUCTION):
    conditions = ["Z","NZ","C","NC","S","NS","O","NO"]
    def __init__(self,cpu,addr):
        INSTRUCTION.__init__(self,cpu,addr)
        self.r14 = None
        self.end = None
        self.r6 = None
        self.cond = None
        self.opcode = None
        self.size = 13
        self.start = 0

    def get_size(self):
        return self.size

    def get_cond(self):
        if self.cond&0xf == 0xf:
            return ""
        elif self.cond&0xf > 7:
            return "-ukn"
        else:
            return "-%s%r" % (self.conditions[self.cond&0xf],self.r14)

    def will_set_flag(self):
        if self.r6 == 0:
            return ""
        else:
            return "-f%r" % (self.r14)

    def str_name(self):
        return self.name() + self.get_cond() + self.will_set_flag()

class UNKNOWN_INSTRUCTION_VM(INSTRUCTION_VM):
    def __init__(self,cpu,addr,r14,end,opcode):
        INSTRUCTION_VM.__init__(self,cpu,addr)
        self.r14 = r14
        self.end = end
        self.opcode = opcode

    def str_name(self):
        return "UKN (%u)" % self.opcode

    def str_parameters(self):
        return "?????????"

class INSTRUCTION2_VM(INSTRUCTION_VM):
    """ Instruction with src and dst parameters """
    def __init__(self,cpu,addr):
        INSTRUCTION_VM.__init__(self,cpu,addr)
        self.src = None
        self.dst = None
        self.sbyte = 2

    def decode(self,data):
        l = len(data)
        self.src,byte1,inst_src = self.cpu.addr_interpretation(data,self.addr)
        self.size += l-len(data)
        l = len(data)
        self.dst,byte2,inst_dst = self.cpu.addr_interpretation(data,self.addr)
        self.size += l-len(data)

        if not inst_src is None:
            self.hidden_instructions.append(inst_src)
        if not inst_dst is None:
            self.hidden_instructions.append(inst_dst)

        if byte1 == 1 or byte2 == 1:
            self.sbyte = 1
            print "ouin"
        return data

    def name(self):
        return self.__class__.__name__ if self.sbyte == 2 else self.__class__.__name__+"B"

    def str_parameters(self):
        return "%s , %s" % (hex(self.src),hex(self.dst))

class INSTRUCTION1_VM(INSTRUCTION_VM):
    """ Instruction with src and dst parameters """
    def __init__(self,cpu,addr):
        INSTRUCTION_VM.__init__(self,cpu,addr)
        self.size += 9
        self.dst = None
        self.r = False
        self.p = None

    def decode(self,data):
        self.right = (data.get_bits(1) == 1)
        self.p = data.get_bits(8)
        l = len(data)
        self.dst,byte,inst = self.cpu.addr_interpretation(data)
        self.size += l-len(data)

        if not inst is None:
            self.hidden_instructions.append(inst)

        if byte == 1:
            self.sbyte = 1
        return data

    def name(self):
        direction = "R" if self.right else "L"
        return "SH" + direction

    def str_parameters(self):
        return "%s , %s" % (hex(self.p),hex(self.dst))

class INSTRUCTION0_VM(INSTRUCTION_VM):
    """ Instruction with src and dst parameters """
    def __init__(self,cpu,addr):
        INSTRUCTION_VM.__init__(self,cpu,addr)
        self.dst = None
        self.sbyte = 2

    def decode(self,data):
        l = len(data)
        self.dst,byte,inst = self.cpu.addr_interpretation(data)
        self.size += l-len(data)

        if not inst is None:
            self.hidden_instructions.append(inst)

        if byte == 1:
            self.sbyte = 1
        return data

    def name(self):
        return self.__class__.__name__ if self.sbyte == 2 else self.__class__.__name__+"B"

    def str_parameters(self):
        return "%s" % (hex(self.dst))

class JMP_VM(INSTRUCTION_VM,JMP):
    """ Instruction with src and dst parameters """
    def __init__(self,cpu,addr):
        JMP.__init__(self,cpu,addr)
        INSTRUCTION_VM.__init__(self,cpu,addr)
        self.dst = None
        self.sbyte = 2
        self.r12 = None
        self.r10 = None
        self.size += 9
        self.inst_name = self.__class__.__name__

    def decode(self,data):
        self.r12 = data.get_bits(6)
        self.r10 = data.get_bits(3)
        self.cpu.sbits = self.cpu.sbits + " %s %s" % (hex(self.r12),hex(self.r10))
        if self.r12 == 0:
            l = len(data)
            self.dst,byte,inst = self.cpu.addr_interpretation(data)
            self.size += l-len(data)

            if not inst is None:
                self.hidden_instructions.append(inst)

                if byte == 1:
                    self.sbyte = 1

        if self.r12 == 0:
            self.goto.append(ADDR(self.cpu,self.dst*8+self.r10))
            self.goto.append(ADDR(self.cpu,self.addr+self.get_size()))
        else:
            if (self.r12 >> 5) == 0:
                self.inst_name = self.inst_name + " +"
                self.goto.append(ADDR(self.cpu,self.addr+self.get_size()+(8*self.r12)+self.r10))
                self.goto.append(ADDR(self.cpu,self.addr+self.get_size()))
            else:
                self.inst_name = self.inst_name + " -"
                self.goto.append(ADDR(self.cpu,self.addr+self.get_size()+((8*self.r12)+self.r10)))
                self.goto.append(ADDR(self.cpu,self.addr+self.get_size()))
        return data

    def name(self):
        return self.inst_name

    def str_additional_info(self):
        if len(self.goto) > 0:
            return "(to %s)" % (hex(self.goto[0]))
        else:
            return "OUIN"

    def str_parameters(self):
        if self.dst is not None:
            return "%s (%r %r)" % (hex(self.dst),hex(self.r12),hex(self.r10))
        else:
            return "%r %r" % (hex(self.r12),hex(self.r10))

class NOT(INSTRUCTION0_VM):
    pass

class MOV(INSTRUCTION2_VM):
    pass

class AND(INSTRUCTION2_VM):
    pass

class OR(INSTRUCTION2_VM):
    pass

class SH(INSTRUCTION1_VM):
    pass

class CALL(JMP_VM):
    pass

class VM(CPU):
    opcodes = [
        OPCODE(AND,0),
        OPCODE(OR,1),
        OPCODE(NOT,2),
        OPCODE(SH,3),
        OPCODE(MOV,4),
        OPCODE(JMP_VM,5),
        OPCODE(CALL,6),
        OPCODE(JMP_VM,7),
        ]

    registers = [REGISTER("r%u"%i) for i in xrange(16)]

    def __init__(self):
        CPU.__init__(self)
        self.r14 = 0
        self.sbits = ""

    def getopcode(self,data,addr):
        if len(data) < 10: return None
        start = data.byte_pos
        r14 = data.get_bits(1)
        cond = data.get_bits(8)
        if r14 == 0:
            cond >>= 4
        opcode = data.get_bits(3)
        r6 = data.get_bits(1)

        self.sbits = "R14:%s R11:%s OPCODE:%s R6:%s" % (hex(r14),hex(cond),hex(opcode),hex(r6))
        if cond == 255:
            return None

        if not opcode in self.hopcodes:
            return UNKNOWN_INSTRUCTION_VM(self,addr,r14,end,opcode)

        inst = self.hopcodes[opcode].name(self,addr)
        inst.start = start
        inst.decode(data)
        inst.r14 = r14
        inst.cond = cond
        inst.r6 = r6
        inst.opcode = opcode
        return inst

    def dis(self,code,data=[]):
        self.ram[:len(code)] = code
        code = DATA_STREAM(code)
        addr = 0
        i = 0
        while len(code) != 0:
            inst = self.getopcode(code,addr)
            if inst is None: break
            self.code.append(inst)
            self.addr2i[addr] = i
            i += 1
            #print self.sbits
            #print "%r ** %u (%s) **" % (inst,inst.size,hex(inst.start))
            #print "----------------------------------------------------------------"
            addr += inst.get_size()

        self.create_xref()

    def addr_interpretation(self,data,addr=0):
        _12e = data.get_bits(1)
        _130 = data.get_bits(2)
        self.sbits = self.sbits + " %s %s" % (hex(_12e),hex(_130))
        if _130 == 0:
            _128 = data.get_bits(4)
            self.sbits = self.sbits + " %s" % (hex(_128))
            return ADDR(self,register=_128),2,None
        elif _130 == 1:
            if _12e == 0:
                r = data.get_bits(8)
                self.sbits = self.sbits + " %s" % (hex(r))
                return r,1,None
            else:
                r = data.get_bits(16)
                self.sbits = self.sbits + " %s" % (hex(r))
                return r,2,None
        elif _130 == 2:
            _132 = data.get_bits(2)
            self.sbits = self.sbits + " %s" % (hex(_132))
            if _132 == 1:
                r = data.get_bits(16)
                self.sbits = self.sbits + " %s" % (hex(r))
                return ADDR(self,addr=r),2,None
            elif _132 == 0:
                r = data.get_bits(4)
                self.sbits = self.sbits + " %s" % (hex(r))
                return ADDR(self,register=r,at=True),2,None
            else:
                r = data.get_bits(16)
                r2 = data.get_bits(4)
                #print hex(addr)
                #if addr == 0x1e39:
                #    r3 = data.get_bits(4)

                self.sbits = self.sbits + " %s %s" % (hex(r),hex(r2))
                return ADDR(self,register=r2,addr=r,at=True),2,None
        else:
            _12a = data.get_bits(16)
            _128 = data.get_bits(4)
            _12c = data.get_bits(6)
            self.sbits = self.sbits + " %s %s %s" % (hex(_12a),hex(_128),hex(_12c))
            return ADDR_VM(self,register=_128,addr=_12a,at=True,obf=_12c),2,None
            #return OPMOVO(_12a,_128,_12c),2,None
