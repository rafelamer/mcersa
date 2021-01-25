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

TARGET = mcersa
OBJECTS = mcersa.o cmdline.o
INCLUDES = cmdline.h

$(TARGET): $(OBJECTS) $(INCLUDES) mcersa.c
	$(CC) -o $(TARGET) $(OBJECTS) $(LIBS)

$(OBJECTS): mcersa.c cmdline.c

cmdline.c: cmdline.ggo
	gengetopt --input=cmdline.ggo

all: $(TARGET)

clean:
	rm -f $(OBJECTS) $(TARGET)
