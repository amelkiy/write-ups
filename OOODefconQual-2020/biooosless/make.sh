#!/bin/sh

cd shellcode

gcc -m32 -Os -fomit-frame-pointer -Wno-builtin-declaration-mismatch -fno-stack-protector -fno-asynchronous-unwind-tables -march=i386 -c read_floppy.c -o read_floppy.o

objcopy -O binary --only-section=entry read_floppy.o entry.bin
objcopy -O binary --only-section=.text read_floppy.o shellcode.bin
cat shellcode.bin >> entry.bin

cp -f entry.bin ../shellcode.bin

cd ..

# With GDB:
# python3 local-run.py shellcode.bin -s -S

# Without GDB:
python3 local-run.py shellcode.bin
