CC=gcc
CFLAGS=-c -g3 -Wall

all: gridbox

gridbox: gridbox.o rules.o
	 $(CC) gridbox.o rules.o -o gridbox

gridbox.o:
	$(CC) $(CFLAGS) gridbox.c

rules.o:
	$(CC) $(CFLAGS) rules.c

install: all
	sudo cp gridbox /usr/sbin/.

clean:
	rm -f *.o gridbox
