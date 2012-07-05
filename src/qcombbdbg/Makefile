TARGET=qcombbdbg
AS=arm-unknown-linux-gnueabi-as
CC=arm-unknown-linux-gnueabi-gcc
LD=arm-unknown-linux-gnueabi-ld
OBJCOPY=arm-unknown-linux-gnueabi-objcopy
SOURCES=qcombbdbg.c abi.c interrupts.c mmu.c core.c trace.c relocator.c
OBJECTS=$(SOURCES:.c=.o)

MODEL=2.5.23Hd

LDSCRIPT=devices/qcombbdbg-$(MODEL).script
LDFLAGS=-Bstatic -x -X -Map $(TARGET).map #--gc-sections

ifneq (,$(findstring clang,$(CC)))
CFLAGS=-cc1 -triple thumbv5-elf-eabi -S -disable-free -disable-llvm-verifier -static-define -mrelocation-model static -mdisable-fp-elim -target-abi aapcs -target-cpu arm926ej-s -msoft-float -mfloat-abi soft -target-feature +soft-float -target-feature +soft-float-abi -backend-option -arm-strict-align -momit-leaf-frame-pointer -g -Oz -ffreestanding -fno-builtin -fno-rtti -fno-common -x c
else
CFLAGS=-mabi=aapcs -Wall -DDEBUG -g -Os -mcpu=arm926ej-s -Wno-unused-function -static -nostdlib -nodefaultlibs -fno-common -fno-strict-aliasing -mthumb -mthumb-interwork -fno-toplevel-reorder  #-fno-inline
endif

all: $(OBJECTS) link

%.o: %.c
	$(CC) $(CFLAGS) -S $*.c -o $*.S
	$(AS) $*.S -o $@

link:
	$(LD) $(LDFLAGS) -T $(LDSCRIPT) $(OBJECTS) -o $(TARGET).elf
	$(OBJCOPY) -O binary -j .text -j .bss --set-section-flags .bss=alloc,load,contents $(TARGET).elf $(TARGET).bin

clean:
	rm -f *.map *.o *.bin *.elf *.S

