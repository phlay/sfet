CC = cc 
CFLAGS = -std=gnu99 -Wall -pedantic -O2
LDFLAGS = 

OBJ = utils.o serpent.o omac-serpent.o eax-serpent.o sha512.o pbkdf2-hmac-sha512.o readpass.o venom.o

.PHONY: clean


.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

all:	venom

clean:
	rm -f *~ *.o venom

install: venom
	ln -f venom ~/bin

venom: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ)

