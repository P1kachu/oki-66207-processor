#!/usr/bin/env python3

'''
It's always like this. It starts as an easy, clean parser
But 3 hours later even I don't understand how this fucking format was written
and my script SMELLS like bugs
Well, 3 hours later or as soon as you need to "import re" - THIS is when you
know you're gonna have a good time

Format explanation from Andy Sloane, asm662's author:
    The first field, after the - is S, R, U, 0, or 1 which refers to the
    treatment of the DD flag in the status register. U means don't care, S
    means it sets DD, R means it resets DD, and 0 or 1 means the instruction
    decodes differently depending on the value of DD. For example the A6 opcode
    is either A6,NL,NH which means SUB A, #N16 (NL and NH are the low and high
    parts of the #N16 16-bit literal parameter), but A6,N8 is SUBB A, #N8, so
    you need to check the value of DD to even determine how many bytes to read
    from the instruction. This is the main roadblock to making a disassembler
    -- just because of this, you need to follow basic blocks and track
    execution jump targets. But IDA does that anyhow.

    The next flag is usually N but can be J or V which is just where the next
    instruction is, N for the next one, J for a jump, I for indirect jump
    (return or J [something]), C for conditional jump, L for call, etc. Or so
    it appears. V is a VCAL, just a jump from a vector table, just like an INT
    used for BIOS / DOS / linux system calls on x86.

    And yeah, all the other things are either hex for literal opcodes or S8
    (signed 8 bit), N8 (8 bit literal), N'8 (second 8 bit literal to
    disambiguate), NL/NH (16 bit literal), or <byte>+N for expansion to 0..7
    for the different erN registers.
'''

import sys
import re

output = []

def to_dd_flag(flag):
    if flag == 0 or flag == "0":
        return "DD_FLAG_ZERO"
    elif flag == 1 or flag == "1":
        return "DD_FLAG_ONE"
    elif flag == "S":
        return "DD_FLAG_SET"
    elif flag == "R":
        return "DD_FLAG_RESET"
    elif flag == "U":
        return "DD_FLAG_UNUSED"
    else:
        print("Invalid DD Flag: {0}".format(flag))
        exit(1)

def to_control_flow_flag(flag):
    if flag == "N":
        return "CF_FLAG_NEXT"
    elif flag == "J":
        return "CF_FLAG_JUMP"
    elif flag == "I":
        return "CF_FLAG_INDIRECT_JUMP"
    elif flag == "C":
        return "CF_FLAG_CONDITIONAL_JUMP"
    elif flag == "L":
        return "CF_FLAG_CALL"
    elif flag == "V":
        return "CF_FLAG_VCALL"
    else:
        print("Invalid CF Flag: {0}".format(flag))
        exit(1)



def pprint(output):
    for i in range(len(output)):
        #print(output[i][1][0]) # opcode
        opcodes = ""
        for op in output[i][1]:
            try:
                if type(op) != int and ("IMM" in op or "rel" in op):
                    opcodes += "{0}, ".format(op)
                else:
                    opcodes += "{0}, ".format('0x{:04x}'.format(op))
            except Exception as e:
                print("!!!!!!!", e, output[i])
                opcodes += "{0}, ".format(op)
        # Opcodes, number of opcodes in total, DD flag, control flow (see explanation on top), mnemonic
        dd_flag = to_dd_flag(output[i][2][0])
        cf_flag = to_control_flow_flag(output[i][2][1])
        ida_features = output[i][4]
        string = "        ([" + opcodes + "], " + dd_flag + ", " + cf_flag + ", \"" + output[i][0] + "\", " + ida_features +"),"
        print(string)

    #print(len(output))

with open(sys.argv[1], "r") as f:
    output.append(("ILLEGAL", [0x5], "UN", "Placeholder", "CF_NONE")) # Debug for now
    for line in f.readlines():

        line = line.rstrip().replace("\t", "")
        if line == "" or line.startswith(";"):
            continue

        #if "S16" in line:
        #    print(line)
        #continue
        initial_line = line
        if "N'" in line:
            line = line.replace("N8", "IMM8a").replace("NL,NH", "IMM16La,IMM16Ha")
            line = line.replace("N'8", "IMM8b").replace("N'L,N'H", "IMM16Lb,IMM16Hb")
        else:
            line = line.replace("N8", "IMM8").replace("NL,NH", "IMM16L,IMM16H")
        line = line.replace("N16", "IMM16").replace("N'16", "IMM16b")
        line = line.replace("S8", "SIGNEDIMM8")
        line = line.replace("addr16", "IMM16").replace("addrh", "IMM16H").replace("addrl", "IMM16L")
        line = line.replace("rel8", "REL8")
        n_in_opcode = False # True if the line represents the same operation on all registers
        try:
            _, instruction, flags_affecting_execution, opcodes, ida_features, _ = re.split(r"^([^-]*)-(..) (.*) -(.*)$", line)
        except:
            continue
        ida_features = ida_features.replace("CF_NONE", "0")
        opcodes = opcodes.split(",")
        opcodes_tmp = []
        for opcode in opcodes:
            try:
                opcodes_tmp.append(int("0x{0}".format(opcode), 16))
            except ValueError:
                if "+N" in opcode or "+n" in opcode:
                    n_in_opcode = True
                    opcodes_tmp = opcodes
                    break
                opcodes_tmp.append(opcode)

        opcodes = opcodes_tmp

        #print(line, end=": ")

        instruction = instruction.lower()
        instruction = instruction.replace("j ", "jmp ") if instruction.startswith("j ") else instruction

        if 0 and n_in_opcode:
            #print()
            if ".n" in instruction:
                nb = 8
            elif "ern" in instruction:
                nb = 4
            elif "rn" in instruction:
                nb = 8
            for i in range(nb):
                new_instruction = instruction.replace("ern", "er{0}".format(i))
                new_instruction = new_instruction.replace("rn", "r{0}".format(i))
                new_instruction = new_instruction.replace(".n", ".{0}".format(i))
                new_instruction = new_instruction.replace("+n", "+{0}".format(i))
                new_opcodes = []
                for opcode in opcodes:
                    if "+n" in opcode or "+N" in opcode:
                        new_opcode = opcode[:opcode.find('+')]
                        new_opcode = int("0x{0}".format(new_opcode), 16) + i
                        new_opcodes.append(new_opcode)
                    else:
                        try:
                            new_opcodes.append(int("0x{0}".format(opcode), 16))
                        except Exception as e:
                            new_opcodes.append(opcode)
                #print("   - {0} -- {1} -- {2}".format(new_instruction, hex(new_opcodes[0]).upper(), new_opcodes[1:]))
                output.append((new_instruction, new_opcodes, flags_affecting_execution, initial_line, ida_features))


        else:
            #print("Normal")
            output.append((instruction, opcodes, flags_affecting_execution, initial_line, ida_features))

    pprint(output)
