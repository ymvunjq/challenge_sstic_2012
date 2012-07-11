#!/usr/bin/env python

import os
import readline
import atexit
from cy16 import *
import code


class BREAKPOINT(object):
    def __init__(self,addr_start=None,addr_stop=None,memory_start=None,memory_stop=None,cond=None,kind=None):
        """
        addr_start: beginning of breakpoints
        addr_stop: start of breakpoint
        memory_start/memory_stop: for breakpoint memory, will break if memory is read/written inside the range
        """
        self.addr_start = addr_start
        self.addr_stop = addr_stop if addr_stop is not None else addr_start
        self.memory_start = memory_start
        self.memory_stop = memory_stop if memory_stop is not None else memory_start
        self.cond = cond
        self.kind = kind

    def __str__(self):
        if self.addr_start is None:
            s = "ALL ADDRESS: "
        elif self.addr_start != self.addr_stop:
            s = "[%s:%s]: " % (hex(self.addr_start),hex(self.addr_stop))
        else:
            s = "%s: " % hex(self.addr_start)

        if self.memory_start is not None:
            if self.memory_start != self.memory_stop:
                s = s + "MEMORY CHECKED : {%s:%s}" % (hex(self.memory_start),hex(self.memory_stop))
            else:
                s = s + "MEMORY CHECKED : {%s}" % (hex(self.memory_start))

        if not self.kind is None:
            s = s + " KIND:%c" % self.kind
        if not self.cond is None:
            s = s + " COND:(%s)" % self.cond
        return s

    def __repr__(self):
        return self.__str__()

    def shall_break(self,debugguer):
        inst = debugguer.cpu.get_inst()
        if self.addr_start is not None and (inst.addr < self.addr_start or inst.addr > self.addr_stop):
            return False
        if self.kind is not None:
            cond = eval(self.cond) if self.cond is not None else lambda d:True
            if self.kind == "w":
                if hasattr(inst,"dst") and isinstance(inst.dst,ADDR) and not inst.dst.is_register():
                    addr = inst.dst.getaddr()
                else:
                    return False
            elif self.kind == "r":
                if hasattr(inst,"src") and isinstance(inst.src,ADDR) and not inst.src.is_register():
                    addr = inst.src.getaddr()
                else:
                    return False
            if self.memory_start is None or (addr >= self.memory_start and addr <= self.memory_stop):
                return cond(debugguer,addr)
            return False
        else:
            cond = eval(self.cond) if self.cond is not None else lambda d:True
            return cond(debugguer)

class DEBUGUER(code.InteractiveConsole):
    def __init__(self,cpu,context,histfile="history.txt"):
        self.cpu = cpu
        self.context = context
        code.InteractiveConsole.__init__(self)
        self.init_history(histfile)
        self.breakpoints = []
        self.handles = {}

    def init_history(self, histfile):
        readline.parse_and_bind("tab: complete")
        if hasattr(readline, "read_history_file"):
            try:
                readline.read_history_file(histfile)
            except IOError:
                pass
            atexit.register(self.save_history, histfile)

    def save_history(self, histfile):
        readline.write_history_file(histfile)

    def input_cmd(self,prompt):
        io = raw_input(prompt)
        cmd = io.split(" ")
        debug_cmd = "cmd_" + cmd[0]
        if hasattr(self,debug_cmd):
            if len(cmd) == 1:
                getattr(self,debug_cmd)()
                return "\n"
            else:
                getattr(self,debug_cmd)(*cmd[1:])
                return "\n"
        else:
            return io

    def run(self):
        code.interact(readfunc=self.input_cmd,local=self.context)

    def display_inst(self):
        i = self.cpu.get_inst()
        print "%s\t%s" % (hex(i.addr)[2:].rjust(4,"0"),i)
        if hasattr(i,"dst") and hasattr(i,"src"):
            if isinstance(i.src,ADDR):
                src = i.src.getval()
            else:
                src = i.src
            print "%r <- %s\n" % (i.dst,hex(src))

    def cmd_start(self,ep):
        if ep[0:2] == "0x":
            ep = int(ep,16)
        else:
            ep = int(ep)
        self.cpu.pc = ep
        self.cpu.disinst()

    def cmd_b(self,addr):
        addr = int(addr,16)
        self.breakpoints.append(BREAKPOINT(addr))

    def cmd_bc(self,addr,*cond):
        addr = int(addr,16)
        cond = " ".join(cond)
        self.breakpoints.append(BREAKPOINT(addr,cond=cond))

    def cmd_dab(self):
        self.breakpoints = []

    def cmd_db(self,indice):
        indice = int(indice)
        del self.breakpoints[indice]

    def cmd_lb(self):
        print "BREAKPOINTS: "
        for i in xrange(len(self.breakpoints)):
            print "%u => %s" % (i,str(self.breakpoints[i]))

    def cmd_s(self):
        addr = self.cpu.exec_next()
        self.display_inst()
        if addr in self.handles:
            exec(self.handles[addr])

    def cmd_n(self):
        inst = self.cpu.get_inst()
        next_inst = inst.addr + inst.get_size()
        self.cmd_b(hex(next_inst))
        self.cmd_r()
        self.cmd_db(str(len(self.breakpoints)-1))

    def cmd_x(self,param,addr):
        addr = int(addr,16)
        size = int(param)
        for i in xrange(size):
            print "%02x" % ord(self.cpu.ram[addr+i]),

    def cmd_ir(self):
        for i in xrange(len(self.cpu.registers)):
            print "%s => %s" % (self.cpu.registers[i],hex(self.cpu.registers[i].val))

    def cmd_sf(self):
        s = "FLAGS = [ "
        for f in ("Z","C"):
            if self.cpu.is_set_flag(f):
                s = s + f + " "
            else:
                s = s + f.lower()+ " "
        print s+"]"

    def cmd_r(self):
        len_ram = len(self.cpu.ram)
        shall_break = False
        while not shall_break:
            n = self.cpu.exec_next()
            assert len(self.cpu.ram) == len_ram, "RAM SIZE CHANGED %r" % hex(self.cpu.pc)
            #self.cpu.disinst()
            if n in self.handles:
                exec(self.handles[n])
            for i in xrange(len(self.breakpoints)):
                #if b.addr == n:
                #    die("%s %r" % (hex(n),b.shall_break(self)))
                if self.breakpoints[i].shall_break(self):
                    print "BREAKPOINT %u !" % i
                    shall_break = True
                    break
        self.cpu.disinst()

    def cmd_h(self,addr,*handle):
        self.handles[int(addr,16)] = " ".join(handle)

    def cmd_f(self,path):
        """ Execute script """
        f = open(path,"r")
        cmd = f.readlines()
        f.close()
        for c in cmd:
            if c[0] == "#": continue
            if c[-1] == "\n":
                c = c[:-1]
            ct = c.split(" ")
            debug_cmd = "cmd_" + ct[0]
            if not hasattr(self,debug_cmd):
                exec(c)
            else:
                getattr(self,debug_cmd)(*ct[1:])

    def cmd_bw(self,addr_start,addr_stop=None):
        addr_start = int(addr_start,16)
        addr_stop = int(addr_stop,16) if addr_stop is not None else addr_start
        self.breakpoints.append(BREAKPOINT(memory_start=addr_start,memory_stop=addr_stop,kind="w"))

    def cmd_br(self,addr_start,addr_stop=None):
        addr_start = int(addr_start,16)
        addr_stop = int(addr_stop,16) if addr_stop is not None else addr_start
        self.breakpoints.append(BREAKPOINT(memory_start=addr_start,memory_stop=addr_stop,kind="r"))

    def cmd_dis(self,addr,stop="10"):
        stop = int(stop)
        addr = int(addr,16)
        size = 0
        for i in xrange(stop):
            i = self.cpu.get_inst(addr)
            print "%s\t%s" % (hex(i.addr)[2:].rjust(4,"0"),i)
            addr += i.get_size()

class DEBUGUERVM(DEBUGUER):
    def cmd_bvm(self,addr):
        addr = int(addr,16)
        cond = "lambda d:d.cpu.unpack(d.cpu.ram[0x11c:0x11e])*8+d.cpu.unpack(d.cpu.ram[0x11e:0x120]) == %u" % addr
        self.breakpoints.append(BREAKPOINT(0x4ec,cond=cond))

    def will_use_mapped_address(self,addr_start,addr_stop,addr):
        base_address = addr&0xfff0
        mapped_address = 0x54

        if addr > 0x50:
            # Ne fait pas parti des adresses mappees du mips
            return False

        i = self.cpu.get_inst()
        if i.addr < 0xff:
            # Adresse qui transmet au mips, donc c'est normal
            return False

        offset = (addr&0xfff0)/0x10
        mips_range = self.cpu.unpack(self.cpu.ram[offset*2+mapped_address:offset*2+mapped_address+2])&0xfff0
        mips_address = mips_range + (addr&0xf)

        #print "ADDR:%s OFFSET:%s MIPS_RANGE:%s MIPS_ADDRESS:%s" % (hex(addr),hex(offset),hex(mips_range),hex(mips_address))
        return (mips_address >= addr_start and mips_address <= addr_stop)

    def bkmemory(self,addr_start,addr_stop,kind):
        addr_start = int(addr_start,16)
        addr_stop = int(addr_stop,16) if addr_stop is not None else addr_start
        cond = "lambda d,a: d.will_use_mapped_address(%u,%u,a)" % (addr_start,addr_stop)
        self.breakpoints.append(BREAKPOINT(cond=cond,kind=kind))

    def cmd_bvmw(self,addr_start,addr_stop=None):
        self.bkmemory(addr_start,addr_stop,"w")

    def cmd_bvmr(self,addr_start,addr_stop=None):
        self.bkmemory(addr_start,addr_stop,"r")

    def cmd_irvm(self):
        base = 0xfe
        for i in xrange(16):
            print "r%s => %s" % (i,hex(self.cpu.unpack(self.cpu.ram[base+i*2:base+(i+1)*2])))

    def cmd_pcvm(self):
        byte = self.cpu.unpack(self.cpu.ram[0x11c:0x11e])
        bit = self.cpu.unpack(self.cpu.ram[0x11e:0x120])
        print hex(byte*8+bit)
