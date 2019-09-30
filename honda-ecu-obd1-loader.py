import os
from idc import *
from idaapi import *
from struct import unpack as up
from ctypes import *

FIRMWARE_SIZE = 32768 # TODO: Verify
HEADER_SIZE = 0x40
FORMAT_NAME = "OKI 66207"

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

    set_processor_type("oki66207", SETPROC_ALL|SETPROC_FATAL)
    set_compiler_id(COMP_GNU)

    return True



