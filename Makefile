# see config.mk for configuration options
#

include config.mk

CC = gcc
CFLAGS = -std=gnu99 -Wall -pedantic -O2
LDFLAGS = 

AS = nasm
ASFLAGS = -Ox -f elf64


OBJ = utils.o serpent.o omac-serpent.o eax-serpent.o sha512.o pbkdf2-hmac-sha512.o readpass.o venom.o

ifeq ($(USE_ASM), yes)
	OBJ += serpent-x86-64.o
	CFLAGS += -DUSE_ASM
endif

ifeq ($(USE_ASM_AVX), yes)
	OBJ += serpent8x-avx.o
	CFLAGS += -DUSE_ASM_AVX
endif

ifeq ($(HAVE_GETRANDOM), yes)
	CFLAGS += -DHAVE_GETRANDOM
endif


.PHONY: clean all install test
.SUFFIXES: .asm

all: venom

${OBJ}: defaults.h config.mk

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<
.asm.o:
	$(AS) $(ASFLAGS) $< -o $@


venom: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ)

clean:
	rm -f *~ *.o venom
	make -C test clean

install: all
	@mkdir -p ${DESTDIR}${PREFIX}/bin
	install -m 0755 venom ${DESTDIR}${PREFIX}/bin

test:
	make -s -C test
