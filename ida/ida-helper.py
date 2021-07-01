# OKI 66207 HELPERS
# Run this after the initial analysis is done to convert immediates to offsets
# in jump instructions, and things like this (I'll add more stuff if I need it
# during reversing)

from idaapi import *
from idautils import *

MIN_RANGE=0
MAX_RANGE=0x6000

def define_p30_ecu_locations():
    '''
    Mark known addresses and locations in the code (P30 ECU only)
    (Completion of the generic _init_memory() function from the loader, but
    with P30 ECU addresses from www.pgmfi.org/twiki/bin/view/Library/P30.html)
    '''
    # Addresss       Size   Description            Note
    known_data = [
            [0x652,  3,'Injector test bypass #1','Change to J label_065F(03 5F 06)'] ,
            [0x11b6, 1,'VTP/VTS error removal','Change to 30'] ,
            [0x11ca, 1,'VTEC Coolant Temp Check','(0x44 enables, 0xFF disables)'] ,
            [0x1580, 3,'Injector test bypass #2','Change to J label_159A(03 9A 15)'] ,
            [0x1831, 1,'Speed limiter Value','B9 is 180 km/h (115mph); FE is 254 km/h (158 mph)'] ,
            [0x1832, 2,'Speed Limiter Jump Routine','Change from jge label_something (CD 0A) to two NOPs (00 00) to disable speed limiter'] ,
            [0x208d, 3,'O2 heater disable','Change to J label_20C7(03 C7 20)'] ,
            [0x2855, 2,'Checksum Jump Instruction','Change JEQ 2867 (C9 10) to SJ 2867 (CB 10) to disable checksum'] ,
            [0x2b75, 2,'Target Idle RPM', "This is a Little Endian OBD1_16bit RPM''untested''"] ,
            [0x3c6e, 2,'IAC Jump Instruction','Change JEQ 3C71 (C9 01) to JEQ 3C70 (C9 00) to disable IAC error'] ,
            [0x3d06, 2,'VTP/VTS error removale','Change to CB1C'] ,
            [0x3d27, 2,'VTP/VTS error removale','Change to CB16'] ,
            [0x6001, 1,'Vtec enable','0xFF enables, 0x00 disables'] ,
            [0x6002, 1,'Knock Sensor Enable','0xFF enables, 0x00 disables'] ,
            [0x6003, 1,'Oxygen heater Sensor','0xFF enables, 0x00 disables'] ,
            [0x6004, 1,'Barometric Sensor Enable','0xFF enables, 0x00 disables'] ,
            [0x6005, 1,'Oxygen Sensor','0xFF enables, 0x00 disables'] ,
            [0x6006, 1,'Injector Test','0xFF disables, 0x00 enables'] ,
            [0x6009, 1,'EGR System','0xFF enables, 0x00 disables'] ,
            [0x600b, 1,'Speed limiter - normal mode','0x00 enables, 0xFF disables'] ,
            [0x6010, 1,'Vtec VSS check','0x00 enables, 0xFF disables'] ,
            [0x6011, 1,'Debug/Test mode','0xFF enables, 0x00 disables, has a lot of effects - more info hinted at here'] ,
            [0x6012, 2,'Auto/Manual Enable','(no idea) lots of good stuff in this thread needs to be deciphered here'] ,
            [0x6013, 1,'Speed Limiter Setting for debug mode','0x00 disables, 0xFF enables'] ,
            [0x6375, 2,'Low Cam Rev Limit Reset','OBD1_16bit RPM format'] ,
            [0x637b, 2,'Low Cam Rev Limit Set'] ,
            [0x6381, 2,'High Cam Rev Limit Reset'] ,
            [0x6387, 2,'High Cam Rev Limit Set'] ,
            [0x6432, 2,'VTEC Point #1','VTEC Crossover RPM #1 Two OBD1_8bit Low Cam RPM values - first is reset, second is set.'] ,
            [0x6434, 2,'VTEC Point #2','VTEC Crossover RPM #2'] ,
            [0x6436, 2,'VTEC Point #3','VTEC Crossover RPM #3'] ,
            [0x6438, 2,'VTEC Point #4','VTEC Crossover RPM #4'] ,
            [0x6988, 47,'Unkown table','has something to do with IACV pulse'] ,
            [0x7000, 10,'mBar Scale','mBar scale row - OBD1_8bit MBar'] ,
            [0x700a, 20,'Low Cam RPM Scale','Low cam RPM scale row - OBD1_8bit Low Cam RPM values'] ,
            [0x701e, 20,'High RPM Scale','High RPM scale row - OBD1_8bit High Cam RPM values'] ,
            [0x7032, 200,'Low Cam Fuel Table', "10 col x 20 row - OBD1_8bit Fuel''v'' values"] ,
            [0x70fa, 10,'Low Cam Fuel Coeff', "10 col x 1 row - OBD1_8bit Fuel''m'' values"] ,
            [0x7104, 200,'High Cam Fuel Table','10 col x 20 row'] ,
            [0x71cc, 10,'High Cam Fuel Coeff','10 col x 1 row'] ,
            [0x71d6, 100,'Extra Fuel Table LIMP MODE','10 col x 10 row'] ,
            [0x7244, 10,'Extra Fuel Coeff','10 col x 1 row'] ,
            [0x724e, 200,'Low Cam Ignition Table','10 col x 20 row - OBD1_8bit Advance values'] ,
            [0x7316, 200,'High Cam Ignition Table','10 col x 20 row'] ,
            [0x73de, 100,'Extra Ignition Table LIMP MODE','10 col x 10 row'] ,
            [0x744c, 200,'Low Cam Table - CLOSE LOOP (target lambda)','10 col x 20 row'] ,
            [0x7514, 200,'High Cam Table - CLOSE LOOP (target lambda)','10 col x 20 row'] ,
            [0x75dc, 100,'Extra Table - no idea, all 00s','10 col x 10 row']
            ]

    for data in known_data:
        if len(data) == 4:
            MakeRptCmt(data[0], "{0} ({1})".format(data[2], data[3]))
        else:
            MakeRptCmt(data[0], data[2])

        MakeNameEx(data[0], "pgmfi_" + data[2].replace(" ", "_").rstrip().lower(), idc.SN_NOWARN | idc.SN_NOCHECK)



def make_loc_out_of_jumps(range_low, range_high):
    '''
    Jumps definition are not translated as destination for some reason when
    loading the file, so force them

    We could do it for other o_near operands to help Xrefs, but we mostly need
    jumps for the graphs for now
    '''

    i = range_low
    while i < range_high:

        # Get the instruction
        insn = ida_ua.insn_t()
        idaapi.decode_insn(insn, i)
        features = insn.get_canon_feature()

        # If it's a jump, convert destination to offset
        if (features & CF_JUMP):

            # Find which operand is the destination (defined as o_near in loader)
            op_index = 0
            for x in insn.ops:
                if x.type == o_near:
                    destination = x.value
                    op_offset(i, op_index, REF_OFF16)
                    break # assuming there is only one address

                op_index += 1

        # Do the same for CALLS, and make the destination a function
        elif (features & CF_CALL):
            op_index = 0
            for x in insn.ops:
                if x.type == o_near:
                    destination = x.value
                    op_offset(i, op_index, REF_OFF16)
                    MakeFunction(destination)
                    break
                op_index += 1

        # Experimental: Mark all immediate in DATA as offsets
        else:
            op_index = 0
            for x in insn.ops:
                if x.value > 0x6000:
                    op_offset(i, op_index, REF_OFF16)
                op_index += 1


        # Go to next address
        i += insn.size
        continue

def helper_find_code_or_data_that_match(all_of_this, min_range=MIN_RANGE, max_range=MAX_RANGE):

    '''
    Find code/data in disassembly based on text representation only (mnemonic,
    comments, labels, anything)
    example:

        helper_find_code_or_data_that_match(["mb", "off("], 0, 6000)
            Found 78 values matching ['mb', 'off(']
            0x500: mb      off(22h).1, c ()
            0x5a2: mbr     c, off(0cbh) ()
            0x6d7: mb      off(1eh).0, c ()
            0x724: mb      off(2bh).5, c ()
            0x78b: mb      off(1bh).7, c ()
            0x795: mb      off(1bh).6, c ()
            0x1580: mb      off(27h).0, c# injector test bypass #2 ()
            0x158c: mb      off(27h).5, c ()
            ...

    '''

    assert(min_range < max_range)
    assert(type(all_of_this) == list)

    all_of_this = [elt.lower() for elt in all_of_this]
    values = []
    i = min_range
    while i < max_range:
        disasm = GetDisasmEx(i, 0).lower()
        match = True
        for elt in all_of_this:
            if elt not in disasm:
                match = False
                break
        if match:
            values.append((i, disasm))

        add = ItemSize(i)
        i += add if add else 1

    if len(values):
        print("Found {0} values matching {1}".format(len(values), all_of_this))
    for elt in values:
        print("{0}: {1} ({2})".format(hex(elt[0])[:-1], elt[1], GetFunctionName(elt[0])))

    return values

def comment_known_p30_bitvectors(min_range=MIN_RANGE, max_range=MAX_RANGE):
    '''
    Add comment to known bitvector values to help the disassembly (P30 ECU only)
    (not optimized, takes a bit of time)
    '''

    for x in helper_find_code_or_data_that_match(["off(16h).4"], min_range, max_range):
        MakeRptCmt(x[0], "VTEC enable (bitvector)")

    for x in helper_find_code_or_data_that_match(["off(27h).6"], min_range, max_range):
        MakeRptCmt(x[0], "Knock sensor enable enable (bitvector)")

    for x in helper_find_code_or_data_that_match(["off(16h).6"], min_range, max_range):
        MakeRptCmt(x[0], "O2 heater sensor enable (bitvector)")

    for x in helper_find_code_or_data_that_match(["off(27h).4"], min_range, max_range):
        MakeRptCmt(x[0], "Barometric sensor enable (bitvector)")

    for x in helper_find_code_or_data_that_match(["off(19h).1"], min_range, max_range):
        MakeRptCmt(x[0], "O2 sensor enable (bitvector)")

    for x in helper_find_code_or_data_that_match(["off(17h).3"], min_range, max_range):
        MakeRptCmt(x[0], "Injector test (bitvector)")

    for x in helper_find_code_or_data_that_match(["off(27h).7"], min_range, max_range):
        MakeRptCmt(x[0], "byte_6007 (bitvector)")

    for x in helper_find_code_or_data_that_match(["off(16h).1"], min_range, max_range):
        MakeRptCmt(x[0], "byte_6008 (bitvector)")

    for x in helper_find_code_or_data_that_match(["off(16h).7"], min_range, max_range):
        MakeRptCmt(x[0], "EGR system (bitvector)")

    for x in helper_find_code_or_data_that_match(["off(27h).1"], min_range, max_range):
        MakeRptCmt(x[0], "byte_600A (bitvector)")

    for x in helper_find_code_or_data_that_match(["off(16h).3"], min_range, max_range):
        MakeRptCmt(x[0], "Auto/Manual enable (bitvector)")

    for x in helper_find_code_or_data_that_match(["off(16h).2"], min_range, max_range):
        MakeRptCmt(x[0], "Speed limiter enable (bitvector)")

    for x in helper_find_code_or_data_that_match(["off(16h).0"], min_range, max_range):
        MakeRptCmt(x[0], "byte_6014 (bitvector)")

    for x in helper_find_code_or_data_that_match(["off(17h).6"], min_range, max_range):
        MakeRptCmt(x[0], "byte_6015 (bitvector)")

    for x in helper_find_code_or_data_that_match(["off(16h).5"], min_range, max_range):
        MakeRptCmt(x[0], "byte_6016 (bitvector)")

    for x in helper_find_code_or_data_that_match(["PSWL.4"], min_range, max_range):
        MakeRptCmt(x[0], "byte_6017 (bitvector)")

    for x in helper_find_code_or_data_that_match(["off(27h).3"], min_range, max_range):
        MakeRptCmt(x[0], "byte_6018 (maybe byte_600C too) (bitvector)")

    for x in helper_find_code_or_data_that_match(["off(27h).2"], min_range, max_range):
        MakeRptCmt(x[0], "byte_6019 (bitvector)")

    for x in helper_find_code_or_data_that_match(["off(19h).4"], min_range, max_range):
        MakeRptCmt(x[0], "byte_601A (bitvector)")






################ Main
# Mark all the bytes in DATA as data
#for i in range(0x6000, 0x7fff):
#        create_data(i, FF_BYTE, 1, 0)
#make_loc_out_of_jumps(0, 0x6000)
#define_p30_ecu_locations()
#comment_known_p30_bitvectors()
