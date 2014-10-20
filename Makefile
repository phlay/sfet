CC = cc 
CFLAGS = -std=gnu99 -Wall -pedantic -O2
LDFLAGS = 


OBJ = utils.o serpent.o omac-serpent.o eax-serpent.o pbkdf2-omac-serpent.o venom.o

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

all:	venom

clean:
	rm -f *~ *.o venom

install: venom
	ln -f venom ~/bin

venom: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ)

