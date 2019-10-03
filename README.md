IDA Python OKI 66207 Loader and Processor
=========================================

Work in progress for Honda ECUs


### Files

- `honda-ecu-obd1-loader.py` detects that a binary is a Honda ECU (should detect, at some point, when I know the header)
- `oki_66207_processor.py` is the processor file
- (`oki66207.py` is a temporary split of the above file)
- `./helpers/op_to_array.py misc/asm662/src/66207.op` to extract instructions from asm662 files

### Links

- http://wuffs.org/blog/mouse-adventures-part-7
- https://github.com/markjandrews/idatraining/tree/master/exercises/exercise11_processor_module
