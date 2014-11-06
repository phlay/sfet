CC = cc
CFLAGS = -std=gnu99 -Wall -pedantic -O2 -I.. -DSELFTEST
LDFLAGS =

AS = nasm
ASFLAGS = -f elf64 -dSELFTEST

include ../config.mk

OBJ_SHA512 = test-sha512.o sha512.o
OBJ_PBKDF2 = test-pbkdf2.o printvec.o sha512.o pbkdf2-hmac-sha512.o
OBJ_SERPENT = test-serpent.o serpent.o
OBJ_SERPENT_X86_64 = test-serpent.o serpent-noenc.o serpent-x86-64.o
OBJ_SERPENT_AVX = test-serpent8x.o serpent-noenc.o serpent8x-avx.o
OBJ_EAX_SERPENT = test-eax-serpent.o serpent.o eax-serpent.o omac-serpent.o


TESTS = sha512 pbkdf2 serpent eax-serpent

ifeq "$(USE_ASM)" "yes"
	TESTS += serpent-x86-64
endif

ifeq "$(USE_ASM_AVX)" "yes"
	TESTS += serpent-avx
endif


#.SILENT:
.SUFFIXES: .asm
.PHONY: all clean test $(TESTS)

all: test

clean:
	rm -f *~ *.o
	for test in $(TESTS); do rm -f test-$$test; done

test: $(TESTS)

sha512: test-sha512
	@echo "Testing sha512..."
	@./test-sha512

pbkdf2: test-pbkdf2
	@echo "Testing pbkdf2..."
	@./test-pbkdf2

serpent: test-serpent
	@echo "Testing serpent..."
	@./test-serpent

serpent-x86-64: test-serpent-x86-64
	@echo "Testing serpent-x86-64..."
	@./test-serpent-x86-64

serpent-avx: test-serpent-avx
	@echo "Testing serpent-avx..."
	@./test-serpent-avx

eax-serpent: test-eax-serpent
	@echo "Testing eax-serpent..."
	@./test-eax-serpent


# general object rules
#
.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

%.o: ../%.c
	$(CC) -c $(CFLAGS) -o $@ $<

%.o: ../%.asm
	$(AS) $(ASFLAGS) $< -o $@

# special case object rules
#
serpent-noenc.o: ../serpent.c
	$(CC) -c $(CFLAGS) -DUSE_ASM -o $@ $<

test-sha512.o: test-sha512.c sha512-table.h

test-serpent8x.o: test-serpent8x.c serpent128-table.h serpent256-table.h
	$(CC) -c $(CFLAGS) -DUSE_ASM -o $@ $<

test-serpent.o: test-serpent.c serpent128-table.h serpent256-table.h
	$(CC) -c $(CFLAGS) -o $@ $<

test-eax-serpent.o: test-eax-serpent.c eax-serpent-table.h
	$(CC) -c $(CFLAGS) -o $@ $<


# self-test build rules
#
test-sha512: $(OBJ_SHA512)
	$(CC) $(LDFLAGS) $(OBJ_SHA512) -o $@

test-pbkdf2: $(OBJ_PBKDF2)
	$(CC) $(LDFLAGS) $(OBJ_PBKDF2) -o $@

test-serpent: $(OBJ_SERPENT)
	$(CC) $(LDFLAGS) $(OBJ_SERPENT) -o $@

test-serpent-x86-64: $(OBJ_SERPENT_X86_64)
	$(CC) $(LDFLAGS) $(OBJ_SERPENT_X86_64) -o $@

test-serpent-avx: $(OBJ_SERPENT_AVX)
	$(CC) $(LDFLAGS) $(OBJ_SERPENT_AVX) -o $@

test-eax-serpent: $(OBJ_EAX_SERPENT)
	$(CC) $(LDFLAGS) $(OBJ_EAX_SERPENT) -o $@
