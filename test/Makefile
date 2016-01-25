include ../config.mk

CC = gcc
CFLAGS = -std=gnu99 -Wall -pedantic -O2 -I.. -DSELFTEST
LDFLAGS =

AS = nasm
ASFLAGS = -Ox -f elf64 -dSELFTEST


OBJ_SHA512 = test-sha512.o sha512.o utils.o
OBJ_PBKDF2 = test-pbkdf2.o printvec.o sha512.o pbkdf2-hmac-sha512.o utils.o
OBJ_SERPENT = test-serpent.o serpent.o
OBJ_SERPENT_AVX = test-serpent8x.o serpent.o serpent8x-avx.o
OBJ_POLY1305 = test-poly1305.o printvec.o


TESTS = sha512 pbkdf2 serpent poly1305

ifeq "$(USE_ASM_X86_64)" "yes"
	CFLAGS += -DUSE_ASM_X86_64

	OBJ_SERPENT += serpent-x86-64.o
	OBJ_POLY1305 += poly1305-x86-64.o
else
	OBJ_POLY1305 += poly1305.o
endif

ifeq "$(USE_ASM_AVX)" "yes"
	CFLAGS += -DUSE_ASM_AVX

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

serpent-avx: test-serpent-avx
	@echo "Testing serpent-avx..."
	@./test-serpent-avx

poly1305: test-poly1305
	@echo "Testing poly1305..."
	@./test-poly1305

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

test-sha512.o: test-sha512.c sha512-table.h

test-serpent8x.o: test-serpent8x.c serpent128-table.h serpent256-table.h
	$(CC) -c $(CFLAGS) -o $@ $<

test-serpent.o: test-serpent.c serpent128-table.h serpent256-table.h
	$(CC) -c $(CFLAGS) -o $@ $<

test-poly1305.o: test-poly1305.c poly1305-table.h
	$(CC) -c $(CFLAGS) -o $@ $<


# self-test build rules
#
test-sha512: $(OBJ_SHA512)
	$(CC) $(LDFLAGS) $(OBJ_SHA512) -o $@

test-pbkdf2: $(OBJ_PBKDF2)
	$(CC) $(LDFLAGS) $(OBJ_PBKDF2) -o $@

test-serpent: $(OBJ_SERPENT)
	$(CC) $(LDFLAGS) $(OBJ_SERPENT) -o $@

test-serpent-avx: $(OBJ_SERPENT_AVX)
	$(CC) $(LDFLAGS) $(OBJ_SERPENT_AVX) -o $@

test-poly1305: $(OBJ_POLY1305)
	$(CC) $(LDFLAGS) $(OBJ_POLY1305) -o $@
