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

# -----------------------------------------------------------------------------------------------------------------------------------------------------

IDEF_MAGIC_VALUE = 0
IDEF_MASK        = 1
IDEF_MNEMONIC    = 2
IDEF_OP_TYPE     = 3
IDEF_IDA_FEATURE = 4
IDEF_COMMENT     = 5

INSN_DEFS = [
	(0x0000, 0xffff, 'nop',     HTOP_NONE,   0,                       'Nothing'),
	(0x0001, 0xffff, 'clrwdt',  HTOP_NONE,   0,                       'Pre-Clear Watchdog Timer'),
	(0x0002, 0xffff, 'halt',    HTOP_NONE,   CF_STOP,                 'Enter power down mode'),
	(0x0003, 0xffff, 'ret',     HTOP_NONE,   CF_STOP,                 'Return from subroutine'),
	(0x0004, 0xffff, 'reti',    HTOP_NONE,   CF_STOP,                 'Return from interrupt'),
	(0x0005, 0xffff, 'clrwdt2', HTOP_NONE,   0,                       'Pre-Clear Watchdog Timer 2'),
	(0x0080, 0xbf80, 'mov',     HTOP_DATA_A, CF_CHG1|CF_USE2,         '[m] := A'),
	(0x0100, 0xbf80, 'cpla',    HTOP_DATA,   CF_USE1,                 'A := ~[m]'),
	(0x0180, 0xbf80, 'cpl',     HTOP_DATA,   CF_USE1|CF_CHG1,         '[m] := ~[m]'),
	(0x0200, 0xbf80, 'sub',     HTOP_A_DATA, CF_USE1|CF_CHG1|CF_USE2, 'A -= [m]'),
	(0x0280, 0xbf80, 'subm',    HTOP_A_DATA, CF_USE1|CF_USE2|CF_CHG2, '[m] := A - [m]'),
	(0x0300, 0xbf80, 'add',     HTOP_A_DATA, CF_USE1|CF_CHG1|CF_USE2, 'A += [m]'),
	(0x0380, 0xbf80, 'addm',    HTOP_A_DATA, CF_USE1|CF_USE2|CF_CHG2|CF_JUMP, '[m] += A'),
	(0x0400, 0xbf80, 'xor',     HTOP_A_DATA, CF_USE1|CF_CHG1|CF_USE2, 'A ^= [m]'),
	(0x0480, 0xbf80, 'xorm',    HTOP_A_DATA, CF_USE1|CF_USE2|CF_CHG2, '[m] ^= A'),
	(0x0500, 0xbf80, 'or',      HTOP_A_DATA, CF_USE1|CF_CHG1|CF_USE2, 'A |= [m]'),
	(0x0580, 0xbf80, 'orm',     HTOP_A_DATA, CF_USE1|CF_USE2|CF_CHG2, '[m] |= A'),
	(0x0600, 0xbf80, 'and',     HTOP_A_DATA, CF_USE1|CF_CHG1|CF_USE2, 'A &= [m]'),
	(0x0680, 0xbf80, 'andm',    HTOP_A_DATA, CF_USE1|CF_USE2|CF_CHG2, '[m] &= A'),
	(0x0700, 0xbf80, 'mov',     HTOP_A_DATA, CF_CHG1|CF_USE2,         'A := [m]'),
	(0x1000, 0xbf80, 'sza',     HTOP_DATA,   CF_USE1,                 'A := [m]; if (A == 0) skip next'),
	(0x1080, 0xbf80, 'sz',      HTOP_DATA,   CF_USE1,                 'if ([m] == 0) skip next'),
	(0x1100, 0xbf80, 'swapa',   HTOP_DATA,   CF_USE1,                 'A := swapNibbles([m])'),
	(0x1180, 0xbf80, 'swap',    HTOP_DATA,   CF_USE1|CF_CHG1,         '[m] := swapNibbles([m])'),
	(0x1200, 0xbf80, 'sbc',     HTOP_A_DATA, CF_USE1|CF_CHG1|CF_USE2, 'A ^= [m]'),
	(0x1280, 0xbf80, 'sbcm',    HTOP_A_DATA, CF_USE1|CF_USE2|CF_CHG2, '[m] ^= A'),
	(0x1300, 0xbf80, 'adc',     HTOP_A_DATA, CF_USE1|CF_CHG1|CF_USE2, 'A ^= [m]'),
	(0x1380, 0xbf80, 'adcm',    HTOP_A_DATA, CF_USE1|CF_USE2|CF_CHG2, '[m] ^= A'),
	(0x1400, 0xbf80, 'inca',    HTOP_DATA,   CF_USE1,                 'A := [m] + 1'),
	(0x1480, 0xbf80, 'inc',     HTOP_DATA,   CF_USE1|CF_CHG1,         '[m]++'),
	(0x1500, 0xbf80, 'deca',    HTOP_DATA,   CF_USE1,                 'A := [m] - 1'),
	(0x1580, 0xbf80, 'dec',     HTOP_DATA,   CF_USE1|CF_CHG1,         '[m]--'),
	(0x1600, 0xbf80, 'siza',    HTOP_DATA,   CF_USE1,                 'A := [m] + 1; if (A == 0) skip next'),
	(0x1680, 0xbf80, 'siz',     HTOP_DATA,   CF_USE1|CF_CHG1,         '[m]++; if ([m] == 0) skip next'),
	(0x1700, 0xbf80, 'sdza',    HTOP_DATA,   CF_USE1,                 'A := [m] - 1; if (A == 0) skip next'),
	(0x1780, 0xbf80, 'sdz',     HTOP_DATA,   CF_USE1|CF_CHG1,         '[m]--; if ([m] == 0) skip next'),
	(0x1800, 0xbf80, 'rla',     HTOP_DATA,   CF_USE1,                 'A := [m] rotLeft 1'),
	(0x1880, 0xbf80, 'rl',      HTOP_DATA,   CF_USE1|CF_CHG1,         '[m] rotLeft 1'),
	(0x1900, 0xbf80, 'rra',     HTOP_DATA,   CF_USE1,                 'A := [m] rotRight 1'),
	(0x1980, 0xbf80, 'rr',      HTOP_DATA,   CF_USE1|CF_CHG1,         '[m] rotRight 1'),
	(0x1a00, 0xbf80, 'rlca',    HTOP_DATA,   CF_USE1,                 'A := [m] rotLeft 1   (with carry)'),
	(0x1a80, 0xbf80, 'rlc',     HTOP_DATA,   CF_USE1|CF_CHG1,         '[m] rotLeft 1   (with carry)'),
	(0x1b00, 0xbf80, 'rrca',    HTOP_DATA,   CF_USE1,                 'A := [m] rotRight 1  (with carry)'),
	(0x1b80, 0xbf80, 'rrc',     HTOP_DATA,   CF_USE1|CF_CHG1,         '[m] rotRight 1  (with carry)'),
	(0x1d00, 0xbf80, 'tabrd',   HTOP_DATA,   CF_CHG1,                 'TBLH:[m] := program[TBHP:TBLP]'),
	(0x1e80, 0xbf80, 'daa',     HTOP_DATA,   CF_CHG1,                 '[m] = bcdAdjust(A)'),
	(0x1f00, 0xbf80, 'clr',     HTOP_DATA,   CF_USE1|CF_CHG1,         '[m] := 0'),
	(0x1f80, 0xbf80, 'set',     HTOP_DATA,   CF_USE1|CF_CHG1,         '[m] := FFh'),
	(0x0900, 0xff00, 'ret',     HTOP_A_IMM,  CF_CHG1|CF_USE2|CF_STOP, 'A := imm; return'),
	(0x0a00, 0xff00, 'sub',     HTOP_A_IMM,  CF_USE1|CF_CHG1|CF_USE2, 'A -= imm'),
	(0x0b00, 0xff00, 'add',     HTOP_A_IMM,  CF_USE1|CF_CHG1|CF_USE2, 'A += imm'),
	(0x0c00, 0xff00, 'xor',     HTOP_A_IMM,  CF_USE1|CF_CHG1|CF_USE2, 'A ^= imm'),
	(0x0d00, 0xff00, 'or',      HTOP_A_IMM,  CF_USE1|CF_CHG1|CF_USE2, 'A |= imm'),
	(0x0e00, 0xff00, 'and',     HTOP_A_IMM,  CF_USE1|CF_CHG1|CF_USE2, 'A &= imm'),
	(0x0f00, 0xff00, 'mov',     HTOP_A_IMM,  CF_CHG1|CF_USE2,         'A := imm'),
	(0x2000, 0x3800, 'call',    HTOP_ADDR,   CF_CALL|CF_USE1,         'call addr'),
	(0x2800, 0x3800, 'jmp',     HTOP_ADDR,   CF_STOP|CF_USE1,         'jump to addr'),
	(0x3000, 0xbc00, 'set',     HTOP_BIT,    CF_CHG1|CF_USE2,         '[m] := 1'),
	(0x3400, 0xbc00, 'clr',     HTOP_BIT,    CF_CHG1|CF_USE2,         '[m] := 0'),
	(0x3800, 0xbc00, 'snz',     HTOP_BIT,    CF_USE1|CF_USE2,         'if ([m] != 0) skip next'),
	(0x3c00, 0xbc00, 'sz',      HTOP_BIT,    CF_USE1|CF_USE2,         'if ([m] == 0) skip next'),
]

    def init_registers(self):
        """This function parses the
        register table and creates
        corresponding ireg_XXX constants"""
        # register names (non memory mapped)
        self.reg_names = [
            # "acc",
            #"psw",
            "pc",
            # "lrb",
            # "ssp",
            "x1",
            "x2",
            "dp",
            "usp",
            "r0",
            "r1",
            "er0",
            "r2",
            "r3",
            "er1",
            "r4",
            "r5",
            "er2",
            "r6",
            "r7",
            "er3",
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

    def init_instructions():
        # TODO: Verify
        self.instruc = []
        for insn in INSN_DEFS:
            self.instruc.append({'name': insn[IDEF_MNEMONIC], 'feature': insn[IDEF_IDA_FEATURE]})
        self.instruc_end = len(INSN_DEFS)
        self.icode_return = 3 # TODO: fix that
        pass

    def init_registers():
        pass

    def __init__(self):
        idaapi.processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()

def PROCESSOR_ENTRY():
    # Required for each Processor module script. Returns an instance of a class
    # derived from idaapi.processor_t
    return oki66207_processor_t()
