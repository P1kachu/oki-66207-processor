import os
from idc import *
from idaapi import *
from struct import unpack as up
from ctypes import *

FORMAT_NAME = "Honda OBD1 ECU (B series)"
SPECIAL_STRING = [0x00, 0xB5, 0x04, 0x15, 0x57, 0x41, 0x00, 0xC4, 0x30, 0x0F, 0xC9, 0x04, 0x42, 0xD0, 0x84, 0x00, 0x62]
SPECIAL_STRING_BEGIN = 0x3b

def _init_memory():
    table = [
        (0x00, "int_RESET"),
        (0x02, "int_brk"),
        (0x04, "int_WDT"),
        (0x06, "int_NMI"),
        (0x08, "int_INT0"),
        (0x0a, "int_serial_rx"),
        (0x0c, "int_serial_tx"),
        (0x0e, "int_serial_rx_BRG"),
        (0x10, "int_timer_0_overflow"),
        (0x12, "int_timer_0"),
        (0x14, "int_timer_1_overflow"),
        (0x16, "int_timer_1"),
        (0x18, "int_timer_2_overflow"),
        (0x1a, "int_timer_2"),
        (0x1c, "int_timer_3_overflow"),
        (0x1e, "int_timer_3"),
        (0x20, "int_a2d_finished"),
        (0x22, "int_PWM_timer"),
        (0x24, "int_serial_tx_BRG"),
        (0x26, "int_INT1"),
    ]

    for elt in table:
        print("Creating {0} at {1}".format(elt[1], hex(elt[0])))
        MakeUnkn(elt[0], 2)
        create_data(elt[0], FF_WORD, 2, 0)
        MakeName(elt[0], elt[1])
        OpOff(elt[0], 0, 0)

    vcal = 0
    while vcal < 8:
        addr = 0x28 + vcal * 2
        print("Creating VCAL {0} at {1}".format(vcal, hex(addr)))
        MakeUnkn(addr, 2)
        create_data(addr, FF_WORD, 2, 0)
        MakeName(addr, "vcal_{0}".format(vcal))
        OpOff(addr, 0, 0)
        vcal += 1

    '''
    pr = 0
    while pr < 8:
        addr = 0x80 + pr * 8
        MakeUnkn(addr, 8)
        create_data(addr, FF_WORD, 2, 0)
        MakeName(addr, "pr{0}_x1".format(pr))
        create_data(addr + 2, FF_WORD, 2, 0)
        MakeName(addr + 2, "pr{0}_x2".format(pr))
        create_data(addr + 4, FF_WORD, 2, 0)
        MakeName(addr + 4, "pr{0}_dp".format(pr))
        create_data(addr + 6, FF_WORD, 2, 0)
        MakeName(addr + 6, "pr{0}_usp".format(pr))
        pr += 1
    '''


    int_start = get_bytes(0x0, 2)
    int_start_addr = (ord(int_start[1]) << 8) + ord(int_start[0])
    cvar.inf.beginEA = cvar.inf.startIP = int_start_addr + 0x10 # Why do I need to add 0x10 ??



def accept_file(li, n):

    # TODO: Remove
    return FORMAT_NAME

    try:
        li.seek(SPECIAL_STRING_BEGIN)
        special_string = li.read(len(SPECIAL_STRING))
        special_string_bytes = [ord(x) for x in special_string]
        for i in xrange(0, len(SPECIAL_STRING)):
            if special_string_bytes[i] != SPECIAL_STRING[i]:
                return 0
    except:
        # Probably file too small
        return 0

    return FORMAT_NAME

def load_file(li, neflags, fmt):
    if fmt != FORMAT_NAME:
	Warning("Unknown format name: '{0}'".format(fmt))

    # TODO: what follows

    filesize = li.size()
    print("Filesize: {0} ({1})".format(filesize, hex(filesize)))

    set_processor_type("oki66207", SETPROC_ALL|SETPROC_FATAL)
    set_compiler_id(COMP_GNU)
    #cvar.inf.mf = True # Big endian

    #set_selector(1, 0);

    flags = ADDSEG_NOTRUNC|ADDSEG_OR_DIE

    print("Creating segment: ", AddSegEx(0x00, 0x28, 0, 0, saRelPara, scPub, flags)) # Vector Table
    RenameSeg(0x00, "vect_tbl")
    print("Creating segment: ", AddSegEx(0x28, 0x38, 0, 0, saRelPara, scPub, flags)) # VCAL Table
    RenameSeg(0x28, "vcals")
    print("Creating segment: ", AddSegEx(0x38, 0x4000, 0, 0, saRelPara, scPub, flags)) # ROM
    RenameSeg(0x38, "rom")
    print("Creating segment: ", AddSegEx(0x4000, 0xffff, 0, 0, saRelPara, scPub, flags)) # External Memory
    RenameSeg(0x4000, "ext_mem")
    li.file2base(0, 0, filesize, 0)

    _init_memory()

    print("Honda ECU (OBD1) loaded".format(li.size()))
    return True



