#!/usr/bin/env python3

'''
It's always like this. It starts as an easy, clean parser
But 3 hours later even I don't understand how this fucking format was written
and my script SMELLS like bugs
Well, 3 hours later or as soon as you need to "import re" - THIS is when you
know you're gonna have a good time
'''

import sys
import re

output = []

def pprint(output):
    for i in range(len(output)):
        string = "("
        for op in output[i][1]:
            try:
                string += "{0}, ".format('{:04x}'.format(op))
            except:
                string += "{0}, ".format(op)
        string += "0xffff, "
        string += "\"{0}\"".format(output[i][0])
        string += "),"
        print(string)
    print(len(output))

with open(sys.argv[1], "r") as f:
    for line in f.readlines():

        line = line.rstrip().replace("\t", "")
        if line == "" or line.startswith(";"):
            continue

        line = line.replace("N8", "imm8").replace("NL,NH", "imm16L,imm16H")
        n_in_opcode = False # True if the line represents the same operation on all registers
        _, instruction, something, opcodes, _ = re.split(r"^([^-]*)-(..) (.*)$", line)
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
        instruction = instruction.replace("n8", "imm8")
        instruction = instruction.replace("n16", "imm16")


        if n_in_opcode:
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
                output.append((new_instruction, new_opcodes))


        else:
            #print("Normal")
            output.append((instruction, opcodes))

    pprint(output)
