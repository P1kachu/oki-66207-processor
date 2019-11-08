IDA Python OKI 66207 Loader and Processor
=========================================

Work in progress for Honda ECUs.

Usable but not completely verified. Some instruction decoding could be
incomplete/invalid (I'm working on fixing them). Best way to use this project
is to compare the output with asm662's. See Notes below for more information.

I used nios2.py and ht68fb560.py as basis for this project. It's my first time
creating a processor module so there might be obvious mistake that I didn't
see. Feel free to submit corrections. The target for this module is to be able
to reverse 90's/00's Honda ECUs, more specifically Integra Type R's. So most
testing will be done with such firmwares.

### Files

- `honda-ecu-obd1-loader.py` detects that a binary is a Honda ECU (should
  detect, at some point, when I know the header. Right now it accepts
  anything). This file should be added to the `/loaders` folder.
- `oki-66207-processor.py` is the processor file. `oki66207.py` is a temporary
  (?) split of the processor file to avoid having a big array in the main file,
  that slows down editing. Those files should be added to the `/procs` folder.
- The instruction array itself is built using `./helpers/op_to_array.py
  asm662-66207.op.modified`. It started well, but it's a hack too in the end.

### What's left

See `TODO`

If you know how to handle special processor flags in IDA/idapython, I'm curious
(https://reverseengineering.stackexchange.com/q/22423/11827)

### Notes

- This architecture uses a special register bit (DD flag) that affects
  instruction decoding. One byte could lead to two different instructions
  (similar, as it's basically "are we handling WORDs or BYTEs", but still
  different) depending on wether that flag is set or not. That flag can be set
  and reset at runtime which makes static decompilation pretty challenging. IDA
  performs multithreaded analysis so a global flag is not the solution. The
  current implementation keeps track of the DD flag for each instruction. Some
  testing revealed that the flag for some instructions is set/reset by
  different threads (xrefs are partially at fault), which shows that it's not a
  foolproof implementation, but it still does a ok-job.
- The concept of page addressing is hard to handle with only static analysis.
  LRB is the register that holds which page is referenced and its value can be
  changed anytime at runtime. For the same kind of reason DD flag is partly
  handled, "offset instructions" are decoded with the "off" keyword. As the
  exact value can't be computed 100% correctly, I leave this to the reverse
  engineer. When encountering the "off" keyword, please keep in mind that the
  value between the parenthesis is only the offset in the page.

### Links

- http://wuffs.org/blog/mouse-adventures-part-7
- https://github.com/markjandrews/idatraining/tree/master/exercises/exercise11_processor_module


![img](./assets/screenshot.png)
