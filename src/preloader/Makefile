TARGET=preloader
AS=arm-unknown-linux-gnueabi-as
CC=arm-unknown-linux-gnueabi-gcc
LD=arm-unknown-linux-gnueabi-ld
OBJCOPY=arm-unknown-linux-gnueabi-objcopy
SOURCES=preloader.c core.c
OBJECTS=$(SOURCES:.c=.o)

MODEL=2.5.23Hd

LDSCRIPT=devices/preloader-$(MODEL).script
CFLAGS=-g -Os -mcpu=arm926ej-s -Wno-unused-function -static -nostdlib -nodefaultlibs -fno-common -fno-strict-aliasing -mthumb -mthumb-interwork -fno-toplevel-reorder  #-fno-inline
LDFLAGS=-Bstatic -x -X -Map $(TARGET).map #--gc-sections

all: $(OBJECTS) link

%.o: %.c
	$(CC) $(CFLAGS) -S $*.c -o $*.S
	$(CC) $(CFLAGS) -c $*.c -o $@

link:
	$(LD) $(LDFLAGS) -T $(LDSCRIPT) $(OBJECTS) -o $(TARGET).elf
	$(OBJCOPY) -O binary -j .text -j .bss --set-section-flags .bss=alloc,load,contents $(TARGET).elf $(TARGET).bin

clean:
	rm -f *.map *.o *.bin *.elf *.S
