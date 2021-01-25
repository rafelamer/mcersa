OS = $(shell sh -c 'uname -s 2>/dev/null || echo not')
ifeq ($(OS),Minix)
CC = clang
CFLAGS = -g -I. -I/usr/local/include
LIBS = -L/usr/local/lib -lmcersa -lz
else
CC = gcc
CFLAGS = -g -I.
LIBS = -lmcersa -lz
endif

TARGETS = test01 test02

all:
	$(CC) $(CFLAGS) -o test01 test01.c $(LIBS)
	$(CC) $(CFLAGS) -o test02 test02.c $(LIBS)

clean:
	rm -f $(TARGETS) test.der
