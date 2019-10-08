# OKI 66207 Processor
# (c) Stanislas Lejay
#

# For lisibility
from oki66207 import *

'''
Misc information from 66201 spec:
    - Uses DATA and CODE segmentation
    - DD (data bit) is 1 if using WORDS or 0 if using BYTES
    - 66207.op format (x1     -x2x3 x4): See ./helpers/op_to_array.py

'''

class oki66207_processor_t(idaapi.processor_t):
    # IDA id (> 0x8000 for third party)
    id = 0x8123

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
    FL_SIGNED    = 0x01        # value/address is signed, output as such
    FL_VAL32    = 0x02        # 32 bit value / offset from low and high parts
    FL_SUB    = 0x04        # subtract offset from base

    #Global Pointer Node Definition
    GlobalPointerNode = None

    # Global Pointer Value
    GlobalPointer = BADADDR

    # ----------------------------------------------------------------------

    def _is_imm(self, val):
        return val > oki66207.SPECIAL_IMM_VALUE

    def _get_instruction_from_op(self, ea, op):
        for index, definition in enumerate(oki66207.INSN_DEFS):
            if definition[oki66207.IDEF_OPCODES][0] == ord(op):
                match = True
                nb_of_params = len(definition[oki66207.IDEF_OPCODES]) - 1
                if nb_of_params:
                    params = get_bytes(ea + 1, nb_of_params)
                    for p in range(nb_of_params):
                        #print(definition[oki66207.IDEF_OPCODES][p + 1],  ord(params[p]))
                        if not self._is_imm(definition[oki66207.IDEF_OPCODES][p + 1]) and definition[oki66207.IDEF_OPCODES][p + 1] != ord(params[p]):
                            match = False
                            break

                if match:
                    return (definition, index)

        return (None, -1)

    def _fill_operands(self, ea, current, insn):
        nb_of_params = len(current[oki66207.IDEF_OPCODES]) - 1

        if nb_of_params == 0:
            return

        params = get_bytes(ea + 1, nb_of_params)
        params_byte = []
        for i in range(nb_of_params):
            params_byte.append(ord(params[i]))
        params = params_byte

        op_idx = 1
        p = 0
        while p < nb_of_params:
            if self._is_imm(current[oki66207.IDEF_OPCODES][p + 1]):
                if current[oki66207.IDEF_OPCODES][p + 1] == oki66207.SIGNEDIMM8:
                    insn.Operands[op_idx].type = o_imm
		    insn.Operands[op_idx].dtype = dt_byte
		    val = params[p]
                    if val > 0x80:
                        insn.Operands[op_idx].value = -(val - 0x80)
                    else:
                        insn.Operands[op_idx].value = val

                elif current[oki66207.IDEF_OPCODES][p + 1] in (oki66207.IMM8, oki66207.IMM8a, oki66207.IMM8b, oki66207.REL8):
                    insn.Operands[op_idx].type = o_imm
		    insn.Operands[op_idx].dtype = dt_byte
		    insn.Operands[op_idx].value = params[p]

                elif current[oki66207.IDEF_OPCODES][p + 1] in (oki66207.IMM16, oki66207.IMM16b, oki66207.IMM16L):
                    insn.Operands[op_idx].type = o_near
		    insn.Operands[op_idx].dtype = dt_word
		    insn.Operands[op_idx].value = (params[p + 1] << 8) + params[p]
                    p += 1

                elif current[oki66207.IDEF_OPCODES][p + 1] in (oki66207.IMM16H):

                    if current[oki66207.IDEF_OPCODES][p + 2] in (oki66207.IMM16L):
                        print("ERROR - _fill_operands: IMM16H found without IMM16L: {0}".format(hex(ea), current, [hex(x) for x in params]))
                        return 1

                    insn.Operands[op_idx].type = o_near
		    insn.Operands[op_idx].dtype = dt_word
		    insn.Operands[op_idx].value = (params[p] << 8) + params[p + 1]
                    p += 1

                else:
                    print("ERROR - _fill_operands: Unknown operand: {0}".format(current[oki66207.IDEF_OPCODES][p + 1]))
                    return 1

                op_idx += 1
            p += 1

        insn.Operands[0].value = op_idx

        return 0


    def notify_ana(self, insn):
        #print("notify_ana")
        #print("                insn @ {0}".format(hex(insn.ea)))

        opcode = get_bytes(insn.ea, 1)[0]
        current, index = self._get_instruction_from_op(insn.ea, opcode)

        if current == None:
            print("ERROR - notify_ana: Instruction not found: {0}".format(ord(opcode)))
            insn.itype = 0x5
            insn.size = 1
            return 1 # Instruction not found

        insn.itype = index

        if self._fill_operands(insn.ea, current, insn):
            exit(0)

        insn.size = len(current[0])
        #print("                insn: {0} (size: {1}) - {2}".format(insn.itype, insn.size, current))

        return insn.size

    def notify_out_insn(self, ctx):
        print("notify_out_insn")
        print("                ea: {0}".format(hex(ctx.insn.ea)))

        insn = ctx.insn
        itype = insn.itype

        raw_mnem = oki66207.INSN_DEFS[itype][oki66207.IDEF_MNEMONIC].split()
        operand_index = 1 # The first Op is used to keep the number of params
        ctx.out_custom_mnem(raw_mnem[0]) # Output the instruction type

        for elt in raw_mnem[1:]: # We skip the first word
            elt = elt.replace(",", "").lower()
            print("               --> {0}".format(elt))
            try:
                # Is the parameter an immediate of any sort
                as_int = int(elt)
                insn.Op6.value = as_int # Op6 will never be used, so we use it to call ctx.out_value
                ctx.out_value(insn.Op6)
            except Exception as e:
                # Not a number
                if elt == "a": # Register A
                    ctx.out_register('A')

                elif "off" in elt: # Offset in page
                    ctx.out_keyword("off ")
                    continue

                elif "imm" in elt or "rel" in elt: # An immediate that needs to be output from operands
	            ctx.out_one_operand(operand_index)
                    operand_index += 1

                    #if "imm" in elt and not "#" in elt:
                    #    OpOff(insn.ea, 0, 0)

                    if "[x1]" in elt:
                        ctx.out_symbol('[')
                        ctx.out_register("x1")
                        ctx.out_symbol(']')

                    elif "[x2]" in elt:
                        ctx.out_symbol('[')
                        ctx.out_register("x2")
                        ctx.out_symbol(']')

                    elif "." in elt: # A bit in the immediate
                        ctx.out_symbol('.')
                        insn.Op6.value = int(elt[-1:])  # Op6 will never be used, so we use it to call ctx.out_value
                        ctx.out_value(insn.Op6)


                elif "r" in elt or elt in ["dp", "x1", "x2", "usp", "lrb", "psw", "pswh", "pswl", "ssp"] or elt.startswith("["): # Another register
                    if elt.startswith("["):
                        ctx.out_symbol('[')
                        ctx.out_register(elt.upper()[1:-1])
                        ctx.out_symbol(']')
                    else:
                        ctx.out_register(elt.upper())

                else:
                    ctx.out_register(" unknown:{0}".format(elt))

            ctx.out_char(",")
            ctx.out_char(" ")

        ctx.set_gen_cmt()
	ctx.flush_outbuf()
        return True

    def notify_get_autocmt(self, insn):
	return oki66207.INSN_DEFS[insn.itype][oki66207.IDEF_MNEMONIC]

    def notify_out_operand(self, ctx, op):
        #print("notify_out_operand")
        # I only used this function for immediate. Probably not the best way to do
        ctx.out_value(op)
        return True

    def notify_emu(self, insn):
        print("notify_emu")
        print("                insn = {0}".format(insn))
        # TODO: Conditionnal jumps

        features = insn.get_canon_feature()
	flow = (features & CF_STOP) == 0

        if (features & CF_JUMP):
	    dest = insn.Op2.value
	    add_cref(insn.ea, dest, fl_JN)
	    flow = False

        elif (features & CF_CALL):
	    dest = insn.Op2.value
	    add_cref(insn.ea, dest, fl_CN)

	if flow:
	    add_cref(insn.ea, insn.ea + insn.size, fl_F)

        return True


    def init_instructions(self):
        self.instruc = []
        for insn in oki66207.INSN_DEFS:
            mnemonic = insn[oki66207.IDEF_MNEMONIC]
            features = insn[oki66207.IDEF_FEATURES]
            self.instruc.append({'name': mnemonic, 'feature': features})
        self.instruc_start = 0
        self.instruc_end = len(oki66207.INSN_DEFS)
        self.icode_return = 0 # TODO: Check what would be good
        pass

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

    def init_memory(self):
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
	    (0x0e, "int_timer_3"),
	    (0x20, "int_a2d_finished"),
	    (0x22, "int_PWM_timer"),
	    (0x24, "int_serial_tx_BRG"),
	    (0x26, "int_INT1"),
        ]

        for elt in table:
            create_data(elt[0], FF_WORD, 2, 0)
            MakeName(elt[0], elt[1])

    def __init__(self):
        idaapi.processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()
        self.init_memory()


def PROCESSOR_ENTRY():
    # Required for each Processor module script. Returns an instance of a class
    # derived from idaapi.processor_t
    return oki66207_processor_t()
