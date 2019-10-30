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

''' Print a message at each function entry (debugging) '''
FUNCTIONS_ENTRY_PRINT = False

''' Print offset as off(xx) rather than trying to compute an immediate out of potentially erroneous page computations '''
PRINT_OFFSET_LIKE_DASM662 = True

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
        'header': [plnames[0], "Experimental for Honda OBD1 ECUs", "Draft by Stanislas Lejay (P1kachu)"],

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
        '''
        Immediates are limited to two bytes. Instructions definition uses
        placeholders like IMM16 or REL8 that are then converted to values
        bigger than 0x10000 to be reinterpreted later on into immediates
        depending on the instruction decoding process
        '''
        return val > oki66207.SPECIAL_IMM_VALUE

    def _get_current_page(self, ea):
        '''
        For offset computation when PRINT_OFFSET_LIKE_DASM662 is False
        Not verified, based on my understanding
        '''
        return (ea / 0x100) * 0x100

    def _get_instruction_from_op(self, ea, op):
        '''
        Find the instruction corresponding to the bytecode
        '''

        if FUNCTIONS_ENTRY_PRINT:
            print("DEBUG: _get_instruction_from_op {0}".format(hex(ea)))

        for index, definition in enumerate(oki66207.INSN_DEFS):
            if definition[oki66207.IDEF_DD] != oki66207.DD_FLAG_UNUSED:
                # DD is used in instruction decoding. Two instructions can have
                # the same bytecode but different interpretation depending on
                # the value of DD
                # If the DD flag is used in one instruction, before trying to
                # match said instruction to the bytecode, we verify that the DD
                # flag has the correct value
                if definition[oki66207.IDEF_DD] == oki66207.DD_FLAG_ONE and self.ireg_dd != 1:
                    continue
                if definition[oki66207.IDEF_DD] == oki66207.DD_FLAG_ZERO and self.ireg_dd != 0:
                    continue

            # Here we compare the bytecode to the instruction, byte by byte.
            # Placeholders like IMM16 or REL8 are skipped
            if definition[oki66207.IDEF_OPCODES][0] == ord(op):
                match = True
                nb_of_params = len(definition[oki66207.IDEF_OPCODES]) - 1
                if nb_of_params:
                    params = get_bytes(ea + 1, nb_of_params)
                    for p in range(nb_of_params):
                        if not self._is_imm(definition[oki66207.IDEF_OPCODES][p + 1]) and definition[oki66207.IDEF_OPCODES][p + 1] != ord(params[p]):
                            match = False
                            break

                # If the instructio match, we verify if it has any impact on the DD flag. If so, we change it accordingly.
                # TODO: Actual DD flag is global and IDA multithreading fucks it up. Need to find a cleaner way.
                if match:
                    if definition[oki66207.IDEF_DD] == oki66207.DD_FLAG_RESET:
                        self.ireg_dd = 0
                    elif definition[oki66207.IDEF_DD] == oki66207.DD_FLAG_SET:
                        self.ireg_dd = 1
                    else:
                        #MakeComm(ea, "DD:{0}".format(self.ireg_dd))
                        pass
                    split_sreg_range(ea, "dd", self.ireg_dd, SR_auto)

                    # Return the matched instruction
                    return (definition, index)

        return (None, -1)

    def _handle_offsets(self, current, insn):
        '''
        used if PRINT_OFFSET_LIKE_DASM662 is set to False
        Tries to convert offsets into immediates
        Not verified, based on my understanding
        '''

        if FUNCTIONS_ENTRY_PRINT:
            print("DEBUG: _handle_offsets {0}".format(hex(insn.ea)))


        raw_mnem = current[oki66207.IDEF_MNEMONIC].split()
        op_idx = 1
        next_is_offset = False
        for elt in raw_mnem[1:]:

            if elt == "off":
                next_is_offset = True
                continue

            if next_is_offset:
                insn.Operands[op_idx].value += self._get_current_page(insn.ea)

                next_is_offset = False

            try:
                int(elt)
                op_idx += 1
            except Exception as e:
                if "imm" in elt:
                    op_idx += 1


        return insn

    def _fill_operands(self, ea, current, insn):
        '''
        Fill operands used by notify_out_operand by reading the opcodes
        '''

        if FUNCTIONS_ENTRY_PRINT:
            print("DEBUG: _fill_operands {0}".format(hex(ea)))
        itype = insn.itype
        features = oki66207.INSN_DEFS[itype][oki66207.IDEF_FEATURES]
        nb_of_params = len(current[oki66207.IDEF_OPCODES]) - 1

        if nb_of_params == 0:
            return

        # Get params as array of bytes (removed the initial opcode used in the
        # decoding of the instruction [itype])
        params = get_bytes(ea + 1, nb_of_params)
        params_byte = []
        for i in range(nb_of_params):
            params_byte.append(ord(params[i]))
        params = params_byte

        # First Op will hold the total number of Ops (I didn't look for any
        # clever way to do it)
        op_idx = 1
        p = 0
        while p < nb_of_params:
            # param is a placeholder, replace with correct value from byte
            if self._is_imm(current[oki66207.IDEF_OPCODES][p + 1]):
                if current[oki66207.IDEF_OPCODES][p + 1] == oki66207.SIGNEDIMM8:
                    insn.Operands[op_idx].type = o_imm
		    insn.Operands[op_idx].dtype = dt_byte
		    val = params[p]
                    if val > 0x80:
                        insn.Operands[op_idx].value = -(val - 0x80)
                    else:
                        insn.Operands[op_idx].value = val

                elif current[oki66207.IDEF_OPCODES][p + 1] == oki66207.REL8:
                    insn.Operands[op_idx].type = o_imm
		    insn.Operands[op_idx].dtype = dt_word
		    insn.Operands[op_idx].value = params[p]

                elif current[oki66207.IDEF_OPCODES][p + 1] in (oki66207.IMM8, oki66207.IMM8a, oki66207.IMM8b):
                    insn.Operands[op_idx].type = o_imm
		    insn.Operands[op_idx].dtype = dt_byte
		    insn.Operands[op_idx].value = params[p]

                elif current[oki66207.IDEF_OPCODES][p + 1] in (oki66207.IMM16, oki66207.IMM16b, oki66207.IMM16L, oki66207.IMM16Lb, oki66207.IMM16La):
                    insn.Operands[op_idx].type = o_near
		    insn.Operands[op_idx].dtype = dt_word
		    insn.Operands[op_idx].value = (params[p + 1] << 8) + params[p]
                    p += 1

                # Handle case where a 16 bits value is split over two bytes
                elif current[oki66207.IDEF_OPCODES][p + 1] in (oki66207.IMM16H, oki66207.IMM16Ha, oki66207.IMM16Hb):

                    if current[oki66207.IDEF_OPCODES][p + 2] not in (oki66207.IMM16L, oki66207.IMM16La, oki66207.IMM16Lb):
                        print("ERROR - _fill_operands: IMM16H found without IMM16L: {0}".format(hex(ea), current, [hex(x) for x in params]))
                        print("Should not happen")
                        return 1

                    insn.Operands[op_idx].type = o_near
		    insn.Operands[op_idx].dtype = dt_word
		    insn.Operands[op_idx].value = (params[p] << 8) + params[p + 1]
                    p += 1

                else:
                    print(current)
                    print("ERROR - _fill_operands: Unknown operand: {0}".format(current[oki66207.IDEF_OPCODES][p + 1]))
                    return 1

                op_idx += 1

            else:
                pass

            p += 1

        # Op1 holds the total number of Ops
        insn.Operands[0].value = op_idx

        # If the instruction is a jump, modify parameter accordingly
        if (features & CF_JUMP):
            if oki66207.INSN_DEFS[itype][oki66207.IDEF_CF] == oki66207.CF_FLAG_CONDITIONAL_JUMP:
                insn = self._handle_conditional_jumps(insn, current[oki66207.IDEF_OPCODES][0])
            else:
                insn = self._handle_jumps(insn, current[oki66207.IDEF_OPCODES][0])

        # If PRINT_OFFSET_LIKE_DASM662 is False, modify the value accordingly
        if not PRINT_OFFSET_LIKE_DASM662 and "off" in current[oki66207.IDEF_MNEMONIC]:
            insn = self._handle_offsets(current, insn)

        # If a value is bigger than a byte, turn it into a word
        for x in range(insn.Operands[0].value):
            if insn.Operands[x + 1].value > 0xff:
                insn.Operands[x + 1].dtype = dt_word
                insn.Operands[x + 1].type = o_near

        return 0


    def notify_ana(self, insn):
        '''
        Called when bytecode needs to be turned into instructions
        (MakeCode basically ?)
        '''
        if FUNCTIONS_ENTRY_PRINT:
            print("DEBUG: notify_ana {0}".format(hex(insn.ea)))

        opcode = get_bytes(insn.ea, 1)[0]
        current, index = self._get_instruction_from_op(insn.ea, opcode)

        # If no instruction was found for this particular bytecode, it means
        # that the instruction is invalid or that the DD flag is incorrect. For
        # now, we just replace it with a fake "illegal" instruction
        if current == None:
            print("{2} ERROR - notify_ana: Instruction not found: {0} ({1})".format(ord(opcode), hex(ord(opcode)), hex(insn.ea).replace("L", "")))
            insn.itype = 0x5
            insn.size = len(oki66207.INSN_DEFS[insn.itype][oki66207.IDEF_OPCODES])
            return insn.size # Instruction not found


        # Index of the correct instruction in the big instructions array
        insn.itype = index

        if self._fill_operands(insn.ea, current, insn):
            print("ERROR: _fill_operands returned != 0")
            exit(0) # This really shouldn't happen

        insn.size = len(current[0])
        #print("                insn: {0} (size: {1}) - {2}".format(insn.itype, insn.size, current))

        '''
        # Comment wether DD flag is changed or not depending on certain instructions
        # Freezes IDA for some reason, randomly
        try:
            if current[oki66207.IDEF_DD] == oki66207.DD_FLAG_RESET:
                current_cmt = GetCommentEx(insn.ea, 0)
                if current_cmt == None or current_cmt != "DD set":
                    MakeComm(insn.ea, "DD reset")
            elif current[oki66207.IDEF_DD] == oki66207.DD_FLAG_SET:
                current_cmt = GetCommentEx(insn.ea, 0)
                if current_cmt == None or current_cmt != "DD reset":
                    MakeComm(insn.ea, "DD set")
        except Exception as e:
            print(e)
        '''

        return insn.size

    def _handle_out_insn_any(self, ctx, raw_mnem):
        '''
        Function responsible for printing generic instructions
        '''

        if FUNCTIONS_ENTRY_PRINT:
            print("DEBUG: _handle_out_insn_any {0}".format(hex(ctx.insn.ea)))

        insn = ctx.insn
        itype = insn.itype
        offset_now = False

        # The first Op is used to keep the number of params
        operand_index = 1

        # We skip the first word, which is the instruction "name"
        for elt in raw_mnem[1:]:
            elt = elt.replace(",", "").lower()
            try:
                # Is the parameter an immediate of any sort
                as_int = int(elt)
                insn.Op6.value = as_int # Op6 will never be used, so we use it to call ctx.out_value
                ctx.out_value(insn.Op6)

            except Exception as e:
                print(e)
                # Not a number
                if elt == "a": # Register A
                    ctx.out_register('A')

                elif "off" in elt: # Offset in page
                    if PRINT_OFFSET_LIKE_DASM662:
                        ctx.out_keyword("off(")
                        offset_now = True
                    else:
                        pass

                    continue

                # An immediate that needs to be output from operands
                elif "imm" in elt or "rel" in elt:
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

                    # A bit in the immediate
                    elif "." in elt:

                        if PRINT_OFFSET_LIKE_DASM662 and offset_now:
                            ctx.out_keyword(")")
                            offset_now = False

                        ctx.out_symbol('.')
                        insn.Op6.value = int(elt[-1:])  # Op6 will never be used, so we use it to call ctx.out_value
                        ctx.out_value(insn.Op6)

                else:
                    if elt.startswith("["):
                        ctx.out_symbol('[')
                        ctx.out_register(elt.upper()[1:-1])
                        ctx.out_symbol(']')
                    else:
                        bit = -1
                        if "." in elt:

                            if PRINT_OFFSET_LIKE_DASM662 and offset_now:
                                ctx.out_keyword(")")
                                offset_now = False

                            bit = int(elt[-1:])
                            elt = elt[:-2]

                        # Another register
                        if "r" in elt or elt in ["dp", "x1", "x2", "usp", "lrb", "psw", "pswh", "pswl", "ssp", "c"]:
                            ctx.out_register(elt.upper())
                            if bit > -1:

                                if PRINT_OFFSET_LIKE_DASM662 and offset_now:
                                    ctx.out_keyword(")")
                                    offset_now = False

                                ctx.out_symbol('.')
                                insn.Op6.value = int(bit)  # Op6 will never be used, so we use it to call ctx.out_value
                                ctx.out_value(insn.Op6)

                        else:
                            ctx.out_register("unknown_reg_{0}".format(elt.upper()))

            if PRINT_OFFSET_LIKE_DASM662 and offset_now:
                ctx.out_keyword(")")
                offset_now = False

            # separate each element with a comma
            if elt != raw_mnem[-1]:
                ctx.out_char(",")
                ctx.out_char(" ")



    def notify_out_insn(self, ctx):
        '''
        Display instructions on the screen
        '''

        if FUNCTIONS_ENTRY_PRINT:
            print("DEBUG: notify_out_insn {0}".format(hex(ctx.insn.ea)))

        raw_mnem = oki66207.INSN_DEFS[ctx.insn.itype][oki66207.IDEF_MNEMONIC].split()
        ctx.out_custom_mnem(raw_mnem[0]) # Output the instruction type

        if "vcal" in raw_mnem[0]:
            ctx.out_keyword("vcal_{0}_tbl_entry".format(raw_mnem[1]))
        elif "brk" in raw_mnem[0]:
            ctx.out_keyword("int_brk_tbl_entry")
        else:
            self._handle_out_insn_any(ctx, raw_mnem)

        ctx.set_gen_cmt()
	ctx.flush_outbuf()

        return True

    def notify_get_autocmt(self, insn):
        '''
        If autocomments are switched on, output the IDEF_MNEMONIC parameter of
        the big instructions array
        '''
	return oki66207.INSN_DEFS[insn.itype][oki66207.IDEF_MNEMONIC]

    def notify_out_operand(self, ctx, op):
        '''
        Output an operand
        '''

        if FUNCTIONS_ENTRY_PRINT:
            print("DEBUG: notify_out_operand {0}".format(hex(ctx.insn.ea)))

        # I only used this function for immediate. Probably not the best way to do
        ctx.out_value(op)
        return True


    def _handle_jumps(self, insn, itype):
        '''
        Compute destinations of direct jumps
        '''

        if itype == 0xb0: # jmp [imm16[x1]]
            pass # TODO
        elif itype == 0xb0: # jmp [imm16[x2]]
            pass # TODO
        elif itype == 0xb3: # jmp [signedimm8[usp]]
            pass # TODO
        elif itype == 0xb4: # jmp [off imm8]
            insn.Operands[1].addr = insn.Operands[1].value + insn.ea + insn.size + 2
            insn.Operands[1].value = insn.Operands[1].addr
        elif itype == 0xb5: # jmp [imm8]
            pass
        elif itype == 0xcb: # sj rel8
            insn.Operands[1].addr = insn.Operands[1].value + insn.ea + insn.size + 2
            insn.Operands[1].value = insn.Operands[1].addr
            pass # TODO

        insn.Operands[1].type = o_near

        return insn


    def _handle_conditional_jumps(self, insn, itype):
        '''
        Compute destinations of conditionnal jumps
        '''

        jmp_type = 0

        if itype == 0x30: # jrnz dp, rel8
            jmp_type = 1
        elif itype == 0xc8: # jgt rel8
            jmp_type = 1
        elif itype == 0xc9: # jeq rel8
            jmp_type = 1
        elif itype == 0xca: # jlt rel8
            jmp_type = 1
        elif itype == 0xcd: # jge rel8
            jmp_type = 1
        elif itype == 0xce: # jne rel8
            jmp_type = 1
        elif itype == 0xcf: # jle rel8
            jmp_type = 1
        elif itype >= 0xd8 and itype < 0xe0: # jbr off imm8.x, rel8
            jmp_type = 2
        elif itype >= 0xe8 and itype < 0xf0: # jbs off imm8.x, rel8
            jmp_type = 2

        if jmp_type == 1:
            if insn.Operands[1].value > 128:
                insn.Operands[1].value -= 256
            insn.Operands[1].addr = insn.Operands[1].value + insn.ea + insn.size + 2
            insn.Operands[1].value = insn.Operands[1].addr
            insn.Operands[1].type = o_near
        elif jmp_type == 2:
            if insn.Operands[2].value > 128:
                insn.Operands[2].value -= 256
            insn.Operands[2].addr = insn.Operands[2].value + insn.ea + insn.size + 3 # Verify
            insn.Operands[2].value = insn.Operands[2].addr
            insn.Operands[2].type = o_near
        else:
            print("WARNING: _handle_conditional_jumps: Invalid conditionnal jump: {0}".format(hex(itype)))

        return insn

    def notify_emu(self, insn):
        '''
        Emulate instruction behaviors (workflow, DD flag, stuff like that)
        '''

        if FUNCTIONS_ENTRY_PRINT:
            print("DEBUG: notify_emu {0}".format(hex(insn.ea)))

        features = insn.get_canon_feature()
        mnemonic = oki66207.INSN_DEFS[insn.itype][oki66207.IDEF_MNEMONIC]

        # flow tells wether controlflow should continue to the next instruction
	flow = (features & CF_STOP) == 0

        # TODO: EMU PSW accesses
        if "psw," in mnemonic or "pswh," in mnemonic:
            #MakeRptCmt(insn.ea, "Might affect DD")
            pass

        # TODO: EMU VCALLS

        # Handle jumps/calls destinations, and control flow
        if (features & CF_JUMP):

            # If we are not in a conditional jump, we should not follow with the next instruction
            if oki66207.INSN_DEFS[insn.itype][oki66207.IDEF_CF] != oki66207.CF_FLAG_CONDITIONAL_JUMP:
	        flow = False

	    dest = insn.Operands[insn.Op1.value - 1].addr
	    add_cref(insn.ea, dest, fl_JN)
            #print("Creating jump cref at {0} towards {1}".format(hex(insn.ea), hex(dest)))

        elif (features & CF_CALL):
	    dest = insn.Op2.addr
	    add_cref(insn.ea, dest, fl_CN)
            #print("Creating call cref at {0} towards {1}".format(hex(insn.ea), hex(dest)))

	if flow:
	    add_cref(insn.ea, insn.ea + insn.size, fl_F)
            #print("Creating flow cref at {0} towards {1}".format(hex(insn.ea), hex(insn.ea + insn.size)))

        return True


    def init_instructions(self):
        '''
        Converts the big instruction array to something IDA can understand
        '''

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
        '''
        This function parses the register table and creates corresponding
        ireg_XXX constants
        '''

        # TODO: Verify how to correctly choose registers
        # register names (non memory mapped)
        self.reg_names = [
            # "acc",
            "A",
            "C",
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
            # Special registers
            "dd",
            "cf",
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

        # You should define 2 virtual segment registers for CS and DS (IDA requirement).
        # number of CS register
        self.reg_code_sreg = self.ireg_CS
        # number of DS register
        self.reg_data_sreg = self.ireg_DS

        self.ireg_dd = 0

    def __init__(self):
        idaapi.processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()


def PROCESSOR_ENTRY():
    # Required for each Processor module script. Returns an instance of a class
    # derived from idaapi.processor_t
    return oki66207_processor_t()
