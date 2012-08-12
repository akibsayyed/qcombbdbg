TARGET=preloader
PREFIX=arm-unknown-linux-gnueabi
AS:=$(PREFIX)-as
CC:=$(PREFIX)-gcc
ifdef GCC_VERSION
  CC:=$(CC)-$(GCC_VERSION)
endif
LD:=$(PREFIX)-ld
OBJCOPY:=$(PREFIX)-objcopy
SOURCES=preloader.c string.c core.c

define HELP_USAGE
  
  Usage: make VARIABLE=VALUE [build|rebuild|clean|help]

  Mandatory variables:
    MODEL=<device revision string>      : Targeted device.
                                          See devices/ directory for existing ld scripts.

  Optional variables:
    PREFIX=<toolchain prefix>           : Default is arm-linux-gnueabi.
    GCC_VERSION=<gcc version>           : Version suffix appended to gcc command.
    CC=<name of ARM compiler>           : Define current compiler executable.
    AS=<name of ARM assembler>          : Define current assembler executable.
    LD=<name of linker>                 : Define current linker executable.
    OBJCOPY=<name of objcopy>           : Define current objcopy executable.
    IMAGE_BASE=<base address of code>   : Enforce base address of generated code.

  Example for Option Icon 225 USB stick:
    make MODEL=2.5.23Hd build

  Changing the prefix for your cross-compilation toolchain:
    make MODEL=2.5.23Hd PREFIX=armv5-none-linux-gnueabi build

  Recompiling with clang:
    make MODEL=2.5.23Hd CC=clang clean build


endef

ifneq (, $(findstring help, $(MAKECMDGOALS)))
  $(error $(HELP_USAGE))
endif

ifndef MODEL
  ifeq (, $(findstring clean, $(MAKECMDGOALS)))
    $(error $(HELP_USAGE))
  endif
endif

DEFINES=DEBUG

ifeq (1, $(REUSE_EXTERNAL_STDLIB))
	REUSE_EXTERNAL_STRING_FUNCS=1
endif

ifeq (1, $(REUSE_EXTERNAL_STRING_FUNCS))
	DEFINES+=REUSE_EXTERNAL_STRING_FUNCS
endif

CFLAGS=$(foreach def,$(DEFINES),-D$(def))
LDSCRIPT=devices/$(TARGET)-$(MODEL).script
LDFLAGS=-Bstatic -x -X -Map $(BUILDDIR)/$(TARGET)-$(MODEL).map #--gc-sections
ifneq (,$(IMAGE_BASE))
  LDFLAGS+=-Ttext=$(IMAGE_BASE)
endif

ifeq (clang, $(firstword $(CC)))
CFLAGS+=-cc1 -triple thumbv5-elf-eabi -S -disable-free -disable-llvm-verifier -static-define -mrelocation-model static -mdisable-fp-elim -target-abi aapcs -target-cpu arm926ej-s -msoft-float -mfloat-abi soft -target-feature +soft-float -target-feature +soft-float-abi -backend-option -arm-strict-align -momit-leaf-frame-pointer -g -Oz -ffreestanding -fno-builtin -fno-rtti -fno-common -x c
else
CFLAGS+=-mabi=aapcs -Wall -g -Os -mcpu=arm926ej-s -Wno-unused-function -static -nostdlib -nodefaultlibs -fno-common -fno-strict-aliasing -mthumb -mthumb-interwork -fno-toplevel-reorder #-fno-inline
endif

BUILDDIR=build
TEMPDIR=work
WORKDIR=$(TEMPDIR)/$(MODEL)
OBJECTS=$(patsubst %.c,$(WORKDIR)/%.o,$(SOURCES))


all: build

workdir:
	mkdir -p $(WORKDIR)

build: workdir $(OBJECTS) link

rebuild: clean build

$(WORKDIR)/%.o: %.c
	$(CC) $(CFLAGS) -S $*.c -o $(WORKDIR)/$*.S
	$(AS) $(WORKDIR)/$*.S -o $@

link:
	mkdir -p $(BUILDDIR)
	$(LD) $(LDFLAGS) -T $(LDSCRIPT) $(OBJECTS) -o $(BUILDDIR)/$(TARGET)-$(MODEL).elf
	$(OBJCOPY) -O binary -j .text -j .bss --set-section-flags .bss=alloc,load,contents $(BUILDDIR)/$(TARGET)-$(MODEL).elf $(BUILDDIR)/$(TARGET)-$(MODEL).bin
	cp $(BUILDDIR)/$(TARGET)-$(MODEL).bin $(TARGET).bin
	cp $(BUILDDIR)/$(TARGET)-$(MODEL).elf $(TARGET).elf

clean:
	rm -rf $(WORKDIR)
	rm -f $(BUILDDIR)/*$(MODEL).map $(BUILDDIR)/*$(MODEL).bin $(BUILDDIR)/*$(MODEL).elf $(TARGET).elf $(TARGET).bin

