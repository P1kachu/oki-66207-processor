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

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['oki66207']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['OKI 66207/MSM66207']

    # size of a segment register in bytes
    segreg_size = 0

    # icode of the first instruction
    instruc_start = 0

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #    real_width[0] - number of digits for short floats (only PDP-11 has them)
    #    real_width[1] - number of digits for "float"
    #    real_width[2] - number of digits for "double"
    #    real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    real_width = (0, 0, 0, 0)

    # only one assembler is supported
    assembler = {
        # flag (for data representation)
        'flag' : ASH_HEXF0 | ASD_DECF0 | AS_UNEQU | AS_COLON | ASB_BINF0 | AS_N2CHR,

        # user defined flags (local only for IDP) (optional)
        'uflag' : 0,

        # Assembler name (displayed in menus)
        'name': plnames[0],

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        'header': [plnames[0], "Experimental for Honda OBD1 ECUs"],

        # org directive
        'origin': ".org",

        # end directive
        'end': ".end",

        # comment string (see also cmnt2)
        'cmnt': "#",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #    Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': ".ascii",

        # byte directive
        'a_byte': ".byte",

        # word directive
        'a_word': ".hword",

        # remove if not allowed
        'a_dword': ".word",

        # array keyword. the following
        # sequences may appear:
        #    #h - header
        #    #d - size
        #    #v - value
        #    #s(b,w,l,q,f,d,o) - size specifiers
        #                        for byte,word,
        #                            dword,qword,
        #                            float,double,oword
        'a_dups': "#d dup(#v)",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': "%s dup ?",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': ".equ",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$pc",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "public",

        # "weak"    name keyword. NULL-gen default, ""-do not generate
        'a_weak': ".weak",

        # "extrn" name keyword
        'a_extrn': "extrn",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': ".align",

        # Left and right braces used in complex expressions
        'lbrace': "(",
        'rbrace': ")",

        # % mod    assembler time operation
        'a_mod': "%",

        # & bit and assembler time operation
        'a_band': "&",

        # | bit or assembler time operation
        'a_bor': "|",

        # ^ bit xor assembler time operation
        'a_xor': "^",

        # ~ bit not assembler time operation
        'a_bnot': "~",

        # << shift left assembler time operation
        'a_shl': "<<",

        # >> shift right assembler time operation
        'a_shr': ">>",

        # size of type (format string) (optional)
        'a_sizeof_fmt': ".size %s",

        'flag2': 0,

        # comment close string (optional)
        # this is used to denote a string which closes comments, for example, if the comments are represented with (* ... *)
        # then cmnt = "(*" and cmnt2 = "*)"
        'cmnt2': "",

        # low8 operation, should contain %s for the operand (optional fields)
        'low8': "",
        'high8': "",
        'low16': "%lo",
        'high16': "%hi",

        # the include directive (format string) (optional)
        'a_include_fmt': ".include %s",

        # if a named item is a structure and displayed in the verbose (multiline) form then display the name
        # as printf(a_strucname_fmt, typename)
        # (for asms with type checking, e.g. tasm ideal)
        # (optional)
        'a_vstruc_fmt': "",

        # 3-byte data (optional)
        'a_3byte': "",

        # 'rva' keyword for image based offsets (optional)
        # (see nalt.hpp, REFINFO_RVA)
        'a_rva': "rva"
    } # Assembler

    # ----------------------------------------------------------------------
    # Special flags used by the decoder, emulator and output
    #
    FL_SIGNED    = 0x01        # value/address is signed; output as such
    FL_VAL32    = 0x02        # 32 bit value / offset from low and high parts
    FL_SUB    = 0x04        # subtract offset from base

    #Global Pointer Node Definition
    GlobalPointerNode = None

    # Global Pointer Value
    GlobalPointer = BADADDR

    # ----------------------------------------------------------------------
    # The following callbacks are optional.
    # *** Please remove the callbacks that you don't plan to implement ***

    # ----------------------------------------------------------------------
    # Global pointer manipulations, init, save, load
    #

    def notify_init(self, idp_file):
        return 1


    def notify_oldfile(self, filename):
        """An old file is loaded (already)"""
        pass

    def notify_savebase(self):
        """The database is being saved. Processor module should save its local data"""
        pass


    # ----------------------------------------------------------------------
    # Registers definition
    #

    def init_registers(self):
        """This function parses the
        register table and creates
        corresponding ireg_XXX constants"""
        # register names
        self.reg_names = [
            "acc",
            "psw",
            "pc",
            "lrb",
            "ssp",
            "x1",
            "x2",
            "dp",
            "usp",
            "r0",
            "r1",
            "r2",
            "r3",
            "r4",
            "r5",
            "r6",
            "r7",
            # Fake segment registers
            "CS",
            "DS"
        ]

        # Create the ireg_XXXX constants
        for i in xrange(len(self.reg_names)):
            setattr(self, 'ireg_' + self.reg_names[i], i)

        # Segment register information (use virtual CS and DS registers if your
        # processor doesn't have segment registers):
        self.reg_first_sreg = self.ireg_CS
        self.reg_last_sreg = self.ireg_DS

        # You should define 2 virtual segment registers for CS and DS.

        # number of CS register
        self.reg_code_sreg = self.ireg_CS
        # number of DS register
        self.reg_data_sreg = self.ireg_DS

    def __init__(self):
        idaapi.processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()

def PROCESSOR_ENTRY():
    # Required for each Processor module script. Returns an instance of a class
    # derived from idaapi.processor_t
    return oki66207_processor_t()
