import os
from idc import *
from idaapi import *
from struct import unpack as up
from ctypes import *

FIRMWARE_SIZE = 32768 # TODO: Verify
HEADER_SIZE = 0x44
FORMAT_NAME = "Honda OBD1 ECU (B series)"

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

    cvar.inf.beginEA = cvar.inf.startIP = HEADER_SIZE + 12 # Debug

    #set_selector(1, 0);

    flags = ADDSEG_NOTRUNC|ADDSEG_OR_DIE

    AddSegEx(0, filesize, 0, 1, saRelPara, scPub, flags)
    li.file2base(0, 0, filesize, 0)

    print("Honda ECU (OBD1) loaded".format(li.size()))
    return True



