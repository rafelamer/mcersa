CFLAGS = -O3 -I.
CC = gcc

TARGETS = test01 test02

all:
	$(CC) $(CFLAGS) -o test01 test01.c -lmcersa -lz
	$(CC) $(CFLAGS) -o test02 test02.c -lmcersa -lz

clean:
	rm -f $(TARGETS) test.der


