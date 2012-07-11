#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import struct
import getopt
from Bits import Bits
import pygraphviz as pgv

def die(s,error_code=1):
    print s
    sys.exit(error_code)

class ERROR:
    pass

class MemoryError(ERROR):
    def __init__(self,ram,addr):
        self.ram = ram
        # Addr which raise MemoryError
        self.addr = addr

class OutOfMemory(MemoryError):
    def __init__(self,ram,addr,index):
        MemoryError.__init__(self,ram,addr)
        self.index = index

    def __repr__(self):
        return "OutOfMemory: Access to %s (size is %r) (addr = %r)" % (hex(self.index),len(self.ram),hex(self.addr))

class OPCODE:
    def __init__(self,name,val,*params):
        self.name = name
        self.val = val
        self.params = params

class RAM:
    def __init__(self,cpu,size=1000,word_size=4,endianness="LE"):
        self.size = size
        self.content = "\x00"*size
        self.cpu = cpu
        self.word_size = word_size
        self.endianness = endianness

        if self.word_size == 4:
            self.format = "L"
        elif self.word_size == 2:
            self.format = "H"
        else:
            die("Word size %u not implemented for RAM" % self.word_size)

        if self.endianness == "LE":
            self.format = "<" + self.format
        else:
            self.format = ">" + self.format

    def __getitem__(self,i):
        if isinstance(i,ADDR):
            i = i.getaddr()
            if i >= len(self): raise OutOfMemory(self,self.cpu.pc,i)
        elif isinstance(i,int):
            i = i & 0xffff
            if i >= len(self): raise OutOfMemory(self,self.cpu.pc,i)
        elif isinstance(i,slice):
            start,stop,step = i.start,i.stop,i.step
            start &= 0xffff
            if start >= len(self): raise OutOfMemory(self,self.cpu.pc,start)
            stop &= 0xffff
            i = slice(start,stop,step)

        return self.content[i]

    def __setitem__(self,i,v):
        # Just for checking
        len_ram = len(self)

        if isinstance(v,int):
            v = self._pack(v)

        if isinstance(i,ADDR):
            self.content = self.content[0:i.getaddr()] + v + self.content[i.getaddr()+1:]
        elif isinstance(i,int):
            i = i & 0xffff
            if i >= len(self): raise OutOfMemory(self,self.cpu.pc,stop)
            self.content = self.content[0:i] + v + self.content[i+len(v):]
        elif isinstance(i,slice):
            start,stop,step = i.start,i.stop,i.step
            if start >= len(self) or stop >= len(self):
                raise OutOfMemory(self,self.cpu.pc,stop)
            self.content = self.content[:start] + v + self.content[stop:]

        assert len_ram == len(self), "Size of RAM was modified during modification (addr %s)" % (hex(self.cpu.pc))

    def __len__(self):
        return len(self.content)

    def _pack(self,v):
        return struct.pack(self.format,v)

class ADDR:
    def __init__(self,cpu,addr=None,register=None,at=False):
        self.cpu = cpu
        if not addr is None:
            if isinstance(addr,ADDR):
                self.addr = addr.addr
            elif isinstance(addr,int):
                self.addr = addr
            else:
                self.addr = cpu.unpack(addr)
        else:
            self.addr = None
        self.register = register
        self.at = at

    def is_register(self):
        return self.register is not None and not self.at and self.addr is None

    def is_at_register(self):
        return self.register is not None and self.at and self.addr is None

    def is_register_offset(self):
        return self.register is not None and self.at and self.addr is not None

    def is_addr_ram(self):
        return self.addr is not None

    def _reg(self):
        assert self.register is not None,"Il n'y a pas de registre"
        return self.cpu.registers[self.register]

    def __str__(self):
        if self.is_register():
            return "%s" % (self._reg())
        elif self.is_at_register():
            return "[%s]" % (self._reg())
        elif self.is_register_offset():
            return "[%s+%s]" % (self._reg(),hex(self.addr))
        else:
            return "[%s]" % hex(self.addr)

    def __hex__(self):
        return str(self)

    def __repr__(self):
        s = "<ADDR"
        if self.register is not None:
            s = s + " register=" + str(self._reg())
        if self.addr is not None:
            s = s + " addr=%s" % str(self.addr)
        s = s + ">"
        return s

    def getaddr(self):
        """ Retourne l'adresse """
        if self.is_register():
            assert self.at,"On ne va pas lire en mémoire la valeur d'un registre"
        elif self.is_at_register():
            return self._reg().val
        elif self.is_register_offset():
            return self._reg().val + self.addr
        else:
            return self.addr

    def getval(self,size=2):
        """ Retourne la valeur pointée """
        if self.is_register():
            return self._reg().val
        return self.cpu.unpack(self.cpu.ram[self.getaddr():self.getaddr()+size])

    def setval(self,val,size=2):
        if isinstance(val,ADDR):
            val = val.getval()
        if size == 1:
            val = val & 0xff
        else:
            val = val & 0xffff

        if self.is_register():
            self.cpu.registers[self.register].val = val
        else:
            # Set into RAM
            if self.is_at_register():
                addr = self._reg().val
            elif self.is_register_offset():
                addr = self._reg().val + self.addr
            else:
                addr = self.addr
            self.cpu.ram[addr] = self.cpu.pack(val,size)


    def __and__(self,x):
        if isinstance(x,ADDR):
            return self.getval() & x.getval()
        return self.getval() & x

    def __or__(self,x):
        if isinstance(x,ADDR):
            return self.getval() | x.getval()
        return self.getval() | x

    def __xor__(self,x):
        if isinstance(x,ADDR):
            return self.getval() ^ x.getval()
        return self.getval() ^ x

    def __lshift__(self,x):
        if isinstance(x,ADDR):
            return self.getval() << x.getval()
        return self.getval() << x

    def __rshift__(self,x):
        if isinstance(x,ADDR):
            return self.getval() >> x.getval()
        return self.getval() >> x

    def __eq__(self,x):
        if isinstance(x,ADDR):
            return self.addr == x.addr
        else:
            return self.addr == x

    def __add__(self,x):
        if isinstance(x,ADDR):
            r = self.getval() + x.getval()
        else:
            r = self.getval() + x
        return r

    def __invert__(self):
        return ~self.getval()

    def __radd__(self,x):
        return self+x

    def __sub__(self,x):
        if isinstance(x,ADDR):
            r = self.getval() - x.getval()
        else:
            r = self.getval() - x
        return r

    def __rsub__(self,x):
        if isinstance(x,ADDR):
            r = x.getval() - self.getval()
        else:
            r = x - self.getval()
        return r

    def __hash__(self):
        return self.addr

class REGISTER:
    def __init__(self,name):
        self.name = name
        self.val = 0

    def __str__(self):
        return "$"+self.name

    def __repr__(self):
        return self.__str__()

class CPU(object):
    _flags = ["Z","C"]
    def __init__(self,size_memory=0x1000):
        self.code = []

        # Table de correspondance addresse/indice
        self.addr2i = {}

        self.hopcodes = {}
        for o in self.opcodes:
            self.hopcodes[o.val] = o

        self.ram = RAM(self,size_memory)
        self.pc = 0
        self.flags = Bits(0,7)

    def is_set_flag(self,flags):
        assert flags in self._flags,"Unknown CPU flags : %r" % flags
        return self.flags[self._flags.index(flags)] == 1

    def update_flags(self,val,flags=["Z","C"]):
        if "Z" in flags:
            if val == 0:
                self.flags[self._flags.index("Z")] = 1
                self.ram[0xc000] = self.pack(self.unpack(self.ram[0xc000]) | 1,2)
            else:
                self.flags[self._flags.index("Z")] = 0
                self.ram[0xc000] = self.pack(self.unpack(self.ram[0xc000]) & 0xfe,2)
        if "C" in flags:
            if (val & 0xffff) == val:
                self.ram[0xc000] = self.pack(self.unpack(self.ram[0xc000]) & 0xfd,2)
                self.flags[self._flags.index("C")] = 0
            else:
                self.ram[0xc000] = self.pack(self.unpack(self.ram[0xc000]) | 2,2)
                self.flags[self._flags.index("C")] = 1

    def get_inst(self,addr=None):
        if addr is None:
            addr = self.pc
        i,d = self.getopcode(self.ram[addr:],addr)
        return i

    def disinst(self,addr=None):
        i = self.get_inst(addr)
        print "%s\t%s" % (hex(i.addr)[2:].rjust(4,"0"),self.get_inst(addr))

    def exec_next(self):
        i = self.get_inst()
        self.pc += i.get_size()
        i.run_instructions()
        return self.pc

    def create_xref(self):
        # Construction des XREF
        for i in xrange(len(self.code)):
            if isinstance(self.code[i],CONTROL_INSTRUCTION):
                for g in self.code[i].goto:
                    if g not in self.addr2i:
                        print "Warning: %s point to %s which is not an instruction" % (hex(self.code[i].addr),hex(g))
                        pass
                    else:
                        if isinstance(self.code[i],JMP):
                            self.code[self.addr2i[g]].xref_jmp.append(self.code[i].addr)
                        else:
                            self.code[self.addr2i[g]].xref_call.append(self.code[i].addr)

    def dis(self,code,data=[]):
        self.ram[:len(code)] = code
        size = 0
        i = 0
        while len(code) != 0:
            if len(data) > 0:
                if size == data[0][0]:
                    d = DATA(self,size,code[:data[0][1]-data[0][0]])
                    self.code.append(d)
                    self.addr2i[size] = i
                    i += 1
                    code = code[data[0][1]-data[0][0]:]
                    size += data[0][1]-data[0][0]
                    del data[0]
                    continue
            if len(code) < 4: break
            inst,code = self.getopcode(code,size)
            self.code.append(inst)
            self.addr2i[size] = i
            i += 1
            size += inst.get_size()

        self.create_xref()

    def show_code(self):
        for i in self.code:
            i.show()

    def get_graph(self,complete=False,output="code.png"):
        """ Retourne les données nécessaire pour faire un graphe avec DOT """
        def code_block(b,e,c):
            if c:
                r = ""
                for inst in self.code[b:e+1]:
                    r = r + "%s    %s" % (hex(inst.addr)[2:].rjust(4,"0"),str(inst)) + "\\l"
                    for hinst in inst.hidden_instructions:
                        r = r + "        %s" % (str(hinst)) + "\\l"
            else:
                r = "BLOCK %s" % hex(self.code[b].addr)
            return r+"\\l"

        # Tableau de correspondance block/addr
        addr2block = {}

        # Graph
        G = pgv.AGraph(directed=True)
        G.node_attr['shape'] = 'rectangle'
        G.node_attr['fontname'] = 'Courier-Bold'
        G.node_attr['style'] = 'bold'

        # Decoupage des blocks
        iblk = 0
        start_block = iblk
        while iblk < len(self.code):
            if len(self.code[iblk].xref_jmp) != 0:
                addr2block[start_block] = iblk-1
                start_block = iblk
            if isinstance(self.code[iblk],JMP):
                addr2block[start_block] = iblk
                start_block = iblk+1
            iblk += 1
        addr2block[start_block] = iblk-1

        for b,e in addr2block.items():
            if isinstance(self.code[e],JMP) and not self.code[e].ret:
                first = True
                for g in self.code[e].goto:
                    if not g in self.addr2i:
                        pass
                    else:
                        if isinstance(self.code[e],JMP):
                            if first:
                                color = "green"
                                first = False
                            else:
                                color = "red"
                        elif isinstance(self.code[e],CALL):
                            if first:
                                color = "blue"
                                first = False
                            else:
                                color = "black"
                        G.add_edge(code_block(b,e,complete),code_block(self.addr2i[g],addr2block[self.addr2i[g]],complete),color=color)
            elif not isinstance(self.code[e],JMP):
                if e+1 < len(self.code):
                    G.add_edge(code_block(b,e,complete),code_block(e+1,addr2block[e+1],complete))
            else:
                # RET
                G.add_node(code_block(b,e,complete))
        #print G.string()
        G.layout()
        G.draw(output,prog="dot")


class INSTRUCTION(object):
    def __init__(self,cpu,addr=None):
        self.cpu = cpu
        self.data = ""
        self.xref_jmp = []
        self.xref_call = []
        self.addr = addr
        self.info = None
        self.hidden_instructions = []

    def decode(self,data):
        pass

    def add_data(self,data):
        self.data = self.data + data

    def __repr__(self):
        return "<%s %s>" % (self.str_name(),self.str_parameters())

    def __str__(self):
        info = "  (%s)" % self.info if not self.info is None else ""
        return "%s\t%s%s" % (self.str_name(),self.str_parameters(),info)

    def str_name(self):
        return self.__class__.__name__

    def str_parameters(self):
        return ""

    def str_additional_info(self):
        return ""

    def show(self):
        if self.addr is None:
            addr = " "*4
        else:
            addr = hex(self.addr)[2:].rjust(4,"0")
        print "%s\t%s\t%s%s" % (" ".join(["%02x"%ord(x) for x in self.data]).rjust(17," "),addr,str(self).ljust(35," ").rjust(50," "),self.str_additional_info())
        for i in self.hidden_instructions:
            i.show()

    def get_size(self):
        return len(self.data)

    def run(self):
        """ Run instruction """
        assert False,"Run method not implemented for %s INSTRUCTION (addr:%s)" % (self.str_name(),hex(self.addr))

    def run_instructions(self):
        """ Run instruction and all hidden instructions """
        self.run()
        for i in self.hidden_instructions:
            i.run()

class UNKNOWN_INSTRUCTION(INSTRUCTION):
    def __init__(self,cpu,addr,data):
        INSTRUCTION.__init__(self,cpu,addr)
        self.data = data

    def str_name(self):
        return "UKN"

    def str_parameters(self):
        return "?????????"

class DATA(INSTRUCTION):
    def __init__(self,cpu,addr,data):
        INSTRUCTION.__init__(self,cpu,addr)
        self.data = data

    def str_name(self):
        return "DATA"

    def show(self):
        print "-----------------------------------------------"
        addr = self.addr
        for i in xrange(0,len(self.data),6):
            print "%s%s" % (" ".join(["%02x"%ord(x) for x in self.data[i:i+6]]).ljust(24," "),hex(addr)[2:].rjust(4,"0"))
            addr += 6
        print "-----------------------------------------------"


class INSTRUCTION2(INSTRUCTION):
    """ Instruction with src and dst parameters """
    def __init__(self,cpu,addr):
        INSTRUCTION.__init__(self,cpu,addr)
        self.src = None
        self.dst = None
        self.sbyte = 2

    def decode(self,data):
        opcode = struct.unpack("<H",data[:2])[0]
        self.add_data(data[:2])
        data = data[2:]
        self.src,byte1,consumed_src,inst_src = self.cpu.addr_interpretation((opcode>>6)&0x3f,data)
        self.dst,byte2,consumed_dst,inst_dst = self.cpu.addr_interpretation(opcode&0x3f,data[consumed_src:])

        if not inst_src is None:
            self.hidden_instructions.append(inst_src)
        if not inst_dst is None:
            self.hidden_instructions.append(inst_dst)

        if byte1 == 1 or byte2 == 1:
            self.sbyte = 1
        self.add_data(data[:consumed_src+consumed_dst])
        return data[consumed_src+consumed_dst:]

    def str_name(self):
        return self.__class__.__name__ if self.sbyte == 2 else self.__class__.__name__+"B"

    def str_parameters(self):
        return "%s , %s" % (hex(self.dst),hex(self.src))

class CONTROL_INSTRUCTION(INSTRUCTION):
    conditions = ["Z","NZ","C","NC","S","NS","O","NO","A","BE","G","GE","L","LE"]
    condflags = {"Z":["Z"],"NZ":["z"],"C":["C"],"NC":["c"],"A":["zc"],"BE":["Z","C"]}
    def __init__(self,cpu,addr):
        INSTRUCTION.__init__(self,cpu,addr)
        self.cond = None
        self.goto = []

    def decode(self,data):
        opcode = struct.unpack("<H",data[:2])[0]
        self.cond = ((opcode>>8)&0xF)
        return data

    def condname(self,name):
        """ Return name of instruction depending on condition """
        if self.cond < len(self.conditions):
            name = name[0] + self.conditions[self.cond]
        return "%s" % (name)

    def is_control_taken(self):
        # Inconditionnal
        if self.cond == 0xf:
            return True

        assert self.conditions[self.cond] in self.condflags,"Unknown conditions %r at %s (%s)" % (self.conditions[self.cond],self.addr,hex(self.cpu.registers[11].val))
        for flag in self.condflags[self.conditions[self.cond]]:
            cond = True
            for f in flag:
                # Si majsucule alors le flag doit être mis
                if ord(f) <= ord("Z"):
                    if not self.cpu.is_set_flag(f.upper()):
                        cond = False
                        break
                else:
                    if self.cpu.is_set_flag(f.upper()):
                        cond = False
                        break
            if cond == True:
                return True
        return False

class INSTRUCTION1op(INSTRUCTION):
    def __init__(self,cpu,addr=None,p1=None,dst=None):
        INSTRUCTION.__init__(self,cpu,addr)
        self.p1 = p1
        self.dst = dst

    def decode(self,data):
        opcode = struct.unpack("<H",data[:2])[0]
        self.add_data(data[:2])
        data = data[2:]
        self.p1 = ((opcode>>6)&0x7) + 1
        self.dst,byte,consumed,inst = self.cpu.addr_interpretation(opcode&0x3f,data)

        if not inst is None:
            self.hidden_instructions.append(inst)
        self.add_data(data[:consumed])
        return data[consumed:]

    def str_parameters(self):
        return "%s , %s" % (hex(self.dst),str(self.p1))

class INSTRUCTION1op2(INSTRUCTION1op):
    def __init__(self,cpu,addr):
        INSTRUCTION1op.__init__(self,cpu,addr=addr)

    def str_parameters(self):
        return "%s" % (hex(self.dst))

class INSTRUCTION0op(INSTRUCTION):
     def __init__(self,cpu,addr):
        INSTRUCTION.__init__(self,cpu,addr)

     def decode(self,data):
         self.add_data(data[:2])
         return data[2:]

class JMP(CONTROL_INSTRUCTION):
    def __init__(self,cpu,addr):
        CONTROL_INSTRUCTION.__init__(self,cpu,addr)
        self.offset = None
        self.relative = None
        self.ret = False

    def decode(self,data):
        data = CONTROL_INSTRUCTION.decode(self,data)
        opcode = struct.unpack("<H",data[:2])[0]
        self.add_data(data[:2])
        data = data[2:]

        # JUMP Relative
        if (opcode & (1<<7)) == 0:
            self.relative = True
            if (opcode & (1<<6)) == 0:
                self.offset = (opcode&0x7f)
            else:
                self.offset = -(((~(opcode&0x3f))+1)&0x3f)

            self.goto.append(ADDR(self.cpu,self.addr + self.get_size() + (self.offset*2)))
            if self.cond != 0xf:
                self.goto.append(ADDR(self.cpu,self.addr + self.get_size()))
        # JUMP Absolute
        elif (opcode & 0x3f) != 0b010111:
            self.relative = False
            self.offset,byte,consumed,inst = self.cpu.addr_interpretation(opcode&0x3f,data)

            if not inst is None:
                self.hidden_instructions.append(inst)
            self.add_data(data[:consumed])
            data = data[consumed:]
            self.goto.append(ADDR(self.cpu,self.offset))
            if self.cond != 0xf:
                self.goto.append(ADDR(self.cpu,self.addr + self.get_size()))
        # RET
        else:
            self.ret = True
        return data

    def str_name(self):
        if self.ret:
            return self.condname("RET")
        else:
            return self.condname("JMP")

    def str_parameters(self):
        if not self.ret:
            if self.relative:
                if self.offset > 0:
                    return "+"+hex(self.offset)
                else:
                    return hex(self.offset)
            else:
                return "%s" % hex(self.offset)
        else:
            return ""

    def str_additional_info(self):
        if not self.ret:
            return "(to %s)" % (hex(self.goto[0]))
        else:
            return ""

    def run(self):
        if self.ret:
            if self.is_control_taken():
                r15 = self.cpu.registers[15].val
                self.cpu.pc = self.cpu.unpack(self.cpu.ram[r15:r15+2])
                self.cpu.registers[15].val += 2
        elif self.is_control_taken():
            self.cpu.pc = self.goto[0].getaddr()


class CALL(CONTROL_INSTRUCTION):
    def __init__(self,cpu,addr):
        CONTROL_INSTRUCTION.__init__(self,cpu,addr)
        self.dest = None
        self.int = False

    def decode(self,data):
        data = CONTROL_INSTRUCTION.decode(self,data)
        opcode = struct.unpack("<H",data[:2])[0]
        self.add_data(data[:2])
        data = data[2:]
        consumed = 0
        # CALL
        if (opcode & (1<<7)) != 0:
            self.int = False
            self.dest,byte,consumed,inst = self.cpu.addr_interpretation(opcode&0x3f,data)

            if not inst is None:
                self.hidden_instructions.append(inst)
            self.goto.append(ADDR(self.cpu,self.dest))
        # INT
        else:
            self.int = True
            self.dest = ADDR(self.cpu,opcode&0x7F)

        self.add_data(data[:consumed])
        self.goto.append(ADDR(self.cpu,self.addr + self.get_size()))
        return data[consumed:]

    def str_name(self):
        return "INT" if self.int else self.condname("CALL")

    def str_parameters(self):
        return "%s" % hex(self.dest)

    def run(self):
        if self.int:
            if self.dest == 0x49:
                for i in xrange(len(self.cpu.registers)-1):
                    self.cpu.push(self.cpu.registers[i].val)
            elif self.dest == 0x4a:
                for i in xrange(len(self.cpu.registers)-1):
                    self.cpu.registers[14-i].val = self.cpu.pop()
            elif self.dest == 0x51:
                self.cpu.usb_receive()
            elif self.dest == 0x50:
                self.cpu.usb_sent()
            elif self.dest == 0x59:
                self.cpu.usb_finish()
            else:
                assert False,"INT %r not implemented" % self.dest
        else:
            if self.is_control_taken():
                self.cpu.registers[15].val -= 2
                self.cpu.registers[15].val &= 0xffff
                v = self.cpu.registers[15].val
                self.cpu.ram[v] = self.cpu.pack(self.cpu.pc,2)
                self.cpu.pc = self.goto[0].getaddr()


class MOV(INSTRUCTION2):
    def run(self):
        # PUSH
        if isinstance(self.dst,ADDR) and self.dst.is_at_register() and self.dst.register == 15:
            self.cpu.registers[15].val -= 2

        self.dst.setval(self.src,self.sbyte)

        # POP
        if isinstance(self.src,ADDR) and self.src.is_at_register() and self.src.register == 15:
            self.cpu.registers[15].val += 2

    def str_name(self):
        if isinstance(self.dst,ADDR) and self.dst.is_at_register() and self.dst.register == 15:
            return "PUSH"
        elif isinstance(self.src,ADDR) and self.src.is_at_register() and self.src.register == 15:
            return "POP"
        else:
            return INSTRUCTION2.str_name(self)

    def str_parameters(self):
        if isinstance(self.dst,ADDR) and self.dst.is_at_register() and self.dst.register == 15:
            return hex(self.src)
        elif isinstance(self.src,ADDR) and self.src.is_at_register() and self.src.register == 15:
            return hex(self.dst)
        else:
            return INSTRUCTION2.str_parameters(self)

class ADD(INSTRUCTION2):
    def run(self):
        self.cpu.update_flags(self.src+self.dst,["Z","C","O","S"])
        self.dst.setval(self.src + self.dst,self.sbyte)

class ADDC(INSTRUCTION2):
    pass

class SUB(INSTRUCTION2):
    def run(self):
        self.cpu.update_flags(self.dst-self.src,["Z","C","O","S"])
        self.dst.setval(self.dst-self.src,self.sbyte)

class SUBB(INSTRUCTION2):
    pass

class CMP(INSTRUCTION2):
    def run(self):
        x = self.dst - self.src
        self.cpu.update_flags(x,["Z","C","O","S"])
        self.cpu.last_cmp = self

class AND(INSTRUCTION2):
    def run(self):
        self.dst.setval(self.dst & self.src,self.sbyte)
        self.cpu.update_flags(self.dst.getval(),["Z","S"])

class TEST(INSTRUCTION2):
    pass

class OR(INSTRUCTION2):
    def run(self):
        self.dst.setval(self.dst | self.src,self.sbyte)
        self.cpu.update_flags(self.dst.getval(),["Z","S"])

class XOR(INSTRUCTION2):
    def run(self):
        self.dst.setval(self.dst ^ self.src,self.sbyte)
        self.cpu.update_flags(self.dst.getval(),["Z","S"])

class SHR(INSTRUCTION1op):
    def run(self):
        self.cpu.update_flags(self.dst >> self.p1,["Z","C"])
        self.dst.setval(self.dst >> self.p1,2)

class SHL(INSTRUCTION1op):
    def run(self):
        self.cpu.update_flags(self.dst << self.p1,["Z","C"])
        self.dst.setval(self.dst << self.p1,2)

class ROR(INSTRUCTION1op):
    def run(self):
        x = (self.dst  >> self.p1) | (self.dst << (16-self.p1))
        self.cpu.update_flags(x,["Z","C"])
        self.dst.setval(x,2)

class ROL(INSTRUCTION1op):
    def run(self):
        x = (self.dst << self.p1) | (self.dst >> (16-self.p1))
        self.cpu.update_flags(x,["Z","C"])
        self.dst.setval(x,2)

class ADDI(INSTRUCTION1op):
    def run(self):
        self.dst.setval(self.dst + self.p1,2)
        self.cpu.update_flags(self.dst.getval(),["Z"])

class SUBI(INSTRUCTION1op):
    def run(self):
        self.dst.setval(self.dst - self.p1,2)
        self.cpu.update_flags(self.dst.getval(),["Z"])

class NOT(INSTRUCTION1op2):
    def run(self):
        self.dst.setval(~self.dst)
        self.cpu.update_flags(self.dst.getval(),["Z"])

class STC(INSTRUCTION0op):
    def run(self):
        self.cpu.update_flags(0xFFFFF,["C"])

class CLC(INSTRUCTION0op):
    def run(self):
        self.cpu.update_flags(0x0,["C"])
