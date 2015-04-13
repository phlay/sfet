# see config.mk for configuration options
#

include config.mk

CC = gcc
CFLAGS = -std=gnu99 -Wall -pedantic -O2 -mtune=$(MTUNE)
LDFLAGS =

AS = nasm
ASFLAGS = -Ox -f elf64


OBJ = utils.o cleanup.o buffer.o burn.o burnstack.o readpass.o sha512.o pbkdf2-hmac-sha512.o serpent.o ctr-serpent.o poly1305-serpent.o venom.o

ifeq ($(STATIC), yes)
	LDFLAGS += -static
endif

ifeq ($(HAVE_GETRANDOM), yes)
	CFLAGS += -DHAVE_GETRANDOM
endif

ifeq ($(USE_ASM_X86_64), yes)
	CFLAGS += -DUSE_ASM_X86_64
	OBJ += serpent-x86-64.o poly1305-x86-64.o
else
	OBJ += poly1305.o
endif

ifeq ($(USE_ASM_AVX), yes)
	OBJ += serpent8x-avx.o
	CFLAGS += -DUSE_ASM_AVX
endif


.PHONY: clean all install test
.SUFFIXES: .asm

all: venom

${OBJ}: config.mk

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<
.asm.o:
	$(AS) $(ASFLAGS) $< -o $@

print-%:
	@echo $*=$($*)

venom: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ)

clean:
	rm -f *~ *.o venom check.bin
	make -C test clean

install: all
	@mkdir -p $(DESTDIR)$(PREFIX)/bin
	install -m 0755 venom $(DESTDIR)$(PREFIX)/bin

# test venom binary
test-venom: venom
	@echo "test venom binary..."
	@for pass in A B C; do \
	for pat in 0 rnd; do \
	for size in 1 15 1048577; do \
		echo "testing $$pass / $$pat / $$size..." ; \
		./venom -f -p test-files/password-$${pass}.txt \
			test-files/crypt_$${pass}_$${pat}_$${size}.venom \
			check.bin ; \
		cmp check.bin test-files/test_$${pat}_$${size}.bin ; \
	done done done
	@rm -f check.bin


# test modules separately
test:
	make -s -C test
