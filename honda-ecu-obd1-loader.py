import os
from idc import *
from idaapi import *
from struct import unpack as up
from ctypes import *

FIRMWARE_SIZE = 32768 # TODO: Verify
HEADER_SIZE = 0x100
FORMAT_NAME = "Honda OBD1 ECU (B series)"

def _init_memory():
    table = [
        (0x00, "int_start"),
        (0x02, "int_break"),
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

    int_start = get_bytes(0x0, 2)
    int_start_addr = (ord(int_start[0]) << 8) + ord(int_start[1])
    cvar.inf.beginEA = cvar.inf.startIP = int_start_addr + 0x10 # Why do I need to add 0x10 ??



def accept_file(li, n):

    #if n:
    #    return False

    ##li.seek(0, os.SEEK_END)
    ##file_len = li.tell()
    #if li.size() < FIRMWARE_SIZE:
    #    return False

    #header = li.read(HEADER_SIZE)

    # Until I actually reverse the fw~
    return FORMAT_NAME

def load_file(li, neflags, fmt):
    if fmt != FORMAT_NAME:
	Warning("Unknown format name: '{0}'".format(fmt))

    # TODO: what follows

    filesize = li.size()
    print("Filesize: {0} ({1})".format(filesize, hex(filesize)))

    set_processor_type("oki66207", SETPROC_ALL|SETPROC_FATAL)
    set_compiler_id(COMP_GNU)
    cvar.inf.mf = True # Big endian

    #set_selector(1, 0);

    flags = ADDSEG_NOTRUNC|ADDSEG_OR_DIE

    print("Creating segment: ", AddSegEx(0x00, 0x28, 0, 0, saRelPara, scPub, flags)) # Vector Table
    print("Creating segment: ", AddSegEx(0x28, 0x38, 0, 0, saRelPara, scPub, flags)) # VCAL Table
    print("Creating segment: ", AddSegEx(0x38, 0x4000, 0, 0, saRelPara, scPub, flags)) # ROM
    print("Creating segment: ", AddSegEx(0x4000, 0xffff, 0, 0, saRelPara, scPub, flags)) # External Memory
    li.file2base(0, 0, filesize, 0)

    _init_memory()

    print("Honda ECU (OBD1) loaded".format(li.size()))
    return True



