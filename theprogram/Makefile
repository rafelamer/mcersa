CFLAGS = -g -I.
LIBS = -lmcersa -lz
CC = gcc
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
	rm -f $(OBJECTS) cmdline.c cmdline.h $(TARGET)
