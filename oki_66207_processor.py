# OKI 66207 Processor
# (c) Stanislas Lejay
#

import sys
import idaapi
from idaapi import *

#For Version 7
from ida_auto import *
from ida_bytes import *
from ida_funcs import *
from ida_idaapi import *
from ida_idp import *
from ida_lines import *
from ida_nalt import *
from ida_name import *
from ida_netnode import *
from ida_offset import *
from ida_problems import *
from ida_segment import *
from ida_ua import *
from ida_xref import *
import ida_frame
import idc

class oki66207_processor_t(idaapi.processor_t):
    # IDA id (> 0x8000 for third party)
    id = 0x8000 + 0x1234

    # Processor features
    flag = PRN_HEX | PR_ASSEMBLE | PR_RNAMESOK

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

def PROCESSOR_ENTRY():
    # Required for each Processor module script. Returns an instance of a class
    # derived from idaapi.processor_t
    return oki66207_processor_t()
