import os
from idc import *
from idaapi import *
from struct import unpack as up
from ctypes import *

FIRMWARE_SIZE = 32768 # TODO: Verify
FORMAT_NAME = "OKI 66207"
MaxCodeSection = 7
MaxDataSection = 11

class DolHeader(BigEndianStructure):
    _fields_ = [
            ("text_offsets", c_uint * MaxCodeSection),
            ("data_offsets", c_uint * MaxDataSection),
            ("text_addresses", c_uint * MaxCodeSection),
            ("data_addresses", c_uint * MaxDataSection),
            ("text_sizes", c_uint * MaxCodeSection),
            ("data_sizes", c_uint * MaxDataSection),
            ("bss_address", c_uint),
            ("bss_size", c_uint),
            ("entry_point", c_uint),
            ]

def accept_file(li, n):

    valid_ep = False

    if n:
        return False

    li.seek(0, os.SEEK_END)
    file_len = li.tell()
    if file_len < FIRMWARE_SIZE:
        return False

    # DO CHECKS

    if not valid_ep:
        return False

    return FORMAT_NAME

def load_file(li, neflags, fmt):
	if fmt != FORMAT_NAME:
		Warning("Unknown format name: '{0}'".format(fmt))

        # TODO: what follows

        set_processor_type("PPC", SETPROC_ALL|SETPROC_FATAL)
        set_compiler_id(COMP_GNU)

        header = get_dol_header(li)

        cvar.inf.beginEA = cvar.inf.startIP = header.entry_point
        set_selector(1, 0);

        flags = ADDSEG_NOTRUNC|ADDSEG_OR_DIE

        for i in xrange(MaxCodeSection):

            if header.text_sizes[i] == 0:
                continue

            addr = header.text_addresses[i]
            size = header.text_sizes[i]
            off = header.text_offsets[i]

            AddSegEx(addr, addr + size, 0, 1, saRelPara, scPub, flags)
            RenameSeg(addr, "Code{0}".format(i))
            SetSegmentType(addr, SEG_CODE)
            li.file2base(off, addr, addr + size, 0)

        for i in xrange(MaxDataSection):

            if header.data_sizes[i] == 0:
                continue

            addr = header.data_addresses[i]
            size = header.data_sizes[i]
            off = header.data_offsets[i]

            AddSegEx(addr, addr + size, 0, 1, saRelPara, scPub, flags)
            RenameSeg(addr, "Data{0}".format(i))
            SetSegmentType(addr, SEG_DATA)
            li.file2base(off, addr, addr + size, 0)

        if header.bss_address:
            addr = header.bss_address
            size = header.bss_size

            AddSegEx(addr, addr + size, 0, 1, saRelPara, scPub, flags)
            RenameSeg(addr, "BSS")
            SetSegmentType(addr, SEG_BSS)

        return True



