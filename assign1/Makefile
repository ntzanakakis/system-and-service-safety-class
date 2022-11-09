CC=gcc
CFLAGS=-I.
DEPS = simple_crypto.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

cryptomake: demo.o simple_crypto.o 
	$(CC) -o demo demo.o simple_crypto.o 