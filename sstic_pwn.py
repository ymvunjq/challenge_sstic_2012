#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys,getopt
from cpu import *
from cy16 import CY16
from vm import VM

def usage(exit_code=0):
    print "Usage: %s [options] file" % sys.argv[0]
    print "\t-t | --test : Run test function"
    print "\t-c | --cpu cy16|vm : choose cpu (default cy16)"
    print "\t-g | --graphic output.png: Generate graph of code"
    print "\t-b | --graphic-blocc output.png: Generate graph of code with only block"
    print "\t-d | --debuguer: launch debugger"
    print "\t-o | --offset byte: start at offset byte"
    print "\t-x | --disassemble : disassemble executable"
    print "\t-r | --reference addr : show reference to address"
    print "\t-h | --help : Display this help"
    sys.exit(exit_code)

if __name__ == "__main__":
    try:
        opts = getopt.getopt(sys.argv[1:],"htg:o:dxr:b:c:")
    except getopt.GetoptError, err:
        print str(err)
        usage(1)

    test = False
    disassemble = False
    debugguer = False
    graphic = None
    block_graphic = None
    offset = 0
    reference = None
    cpu = CY16()
    data = [[0x1e,0x7a],[0xfe,0x146],[0x8a8,0xa6e]]

    for opt,param in opts[0]:
        if opt in ("-h","--help"):
            usage(0)
        elif opt in ("-t","--test"):
            test = True
        elif opt in ("-c","--cpu"):
            if param == "cy16":
                cpu = CY16()
                # information that should be considered as data and not opcode
                data = [[0x1e,0x7a],[0xfe,0x146],[0x8a8,0xa6e]]
            elif param == "vm":
                cpu = VM()
                data = []
            else:
                print "Unknown cpu"
                usage(1)
        elif opt in ("-g","--graphic"):
            graphic = param
        elif opt in ("-b","--graphic-bloc"):
            block_graphic = param
        elif opt in ("-o","--offset"):
            offset = int(param)
        elif opt in ("-x","--disassemble"):
            disassemble = True
        elif opt in ("-d","--debuguer"):
            debugguer = True
        elif opt in ("-r","--reference"):
            reference = int(param,16)

    if test:
        _test()
    else:
        if len(opts[1]) == 0:
            print "Missing file !"
            usage(1)
        exe = opts[1][0]

        cpu.dis(open(exe).read()[offset:],data)

        if disassemble:
            cpu.show_code()
        elif reference is not None:
            print "Reference to Address %s : " % hex(reference)
            print "\tJMP => ",
            for x in cpu.code[cpu.addr2i[reference]].xref_jmp:
                print "%s " % hex(x),
            print "\n\tCALL => ",
            for x in cpu.code[cpu.addr2i[reference]].xref_call:
                print "%s " % hex(x),
        elif not graphic is None:
            cpu.get_graph(complete=True,output=graphic)
        elif not block_graphic is None:
            cpu.get_graph(complete=False,output=block_graphic)
        elif debugguer:
            import debuguer
            d = debuguer.DEBUGUERVM(cpu,globals())
            d.run()
