IDA Python OKI 66207 Loader and Processor
=========================================

Work in progress for Honda ECUs.

STILL IN VERY EARLY STAGE

I used nios2.py and ht68fb560.py as basis for this project. It's my first time
creating a processor module so there might be obvious mistake that I didn't
see. Feel free to submit corrections. The target for this module is to be able
to reverse 90's/00's Honda ECUs, more specifically Integra Type R's. So most
testing will be done with such firmwares.


### Files

- `honda-ecu-obd1-loader.py` detects that a binary is a Honda ECU (should detect, at some point, when I know the header. Right now accepts anything)
- `oki-66207-processor.py` is the processor file
- (`oki66207.py` is a temporary split of the above file)
- `./helpers/op_to_array.py asm662-66207.op.modified` to extract instructions from asm662 files

### Links

- http://wuffs.org/blog/mouse-adventures-part-7
- https://github.com/markjandrews/idatraining/tree/master/exercises/exercise11_processor_module
