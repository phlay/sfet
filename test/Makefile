CC = cc 
CFLAGS = -std=gnu99 -Wall -pedantic -O2 -I..
LDFLAGS = 

OBJ_TEST_SHA512 = test-sha512.o ../sha512.o
OBJ_TEST_PBKDF2 = test-pbkdf2.o printvec.o ../sha512.o ../pbkdf2-hmac-sha512.o

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

all:	test

clean:
	rm -f *~ *.o test-sha512 test-pbkdf2

test-sha512: $(OBJ_TEST_SHA512)
	$(CC) $(LDFLAGS) $(OBJ_TEST_SHA512) -o $@ 

test-pbkdf2: $(OBJ_TEST_PBKDF2)
	$(CC) $(LDFLAGS) $(OBJ_TEST_PBKDF2) -o $@ 


test: test-sha512 test-pbkdf2
	@echo "Testing sha512..."
	@./test-sha512
	@echo "Testing pbkdf2..."
	@./test-pbkdf2
	
