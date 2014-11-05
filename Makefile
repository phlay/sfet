# please see config.mk for configuration options
#

CC = gcc
CFLAGS = -std=gnu99 -Wall -pedantic -O2
LDFLAGS = 

AS = nasm
ASFLAGS = -f elf64

include config.mk


OBJ = utils.o serpent.o omac-serpent.o eax-serpent.o sha512.o pbkdf2-hmac-sha512.o readpass.o venom.o

ifeq "$(USE_ASM)" "yes"
	OBJ += serpent-x86-64.o
	CFLAGS += -DUSE_ASM
endif

ifeq "$(USE_ASM_AVX)" "yes"
	OBJ += serpent8x-avx.o
	CFLAGS += -DUSE_ASM_AVX
endif


.PHONY: clean
.SUFFIXES: .asm


.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<
.asm.o:
	$(AS) $(ASFLAGS) $<


all:	venom

clean:
	rm -f *~ *.o venom

install: venom
	ln -f venom ~/bin

venom: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ)

