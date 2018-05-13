CFLAGS = -O3 -fPIC -I.
CC = gcc
OBJECTS = xmalloc.o sputil.o spdivide.o spmultiply.o spfiles.o \
addition.o subtraction.o multiplication.o division.o random.o gcd.o \
modular.o primes.o rsa.o base64.o rsafiles.o encrypt.o decrypt.o \
der.o aes.o des.o md5.o sha1.o arcfour.o blowfish.o md2.o rot-13.o \
sha2.o tiger.o sboxes.o oaep.o spcrypt.o pkcs5_pbkdf2.o cryptaes.o \
signature.o cryptfiles.o

OS = $(shell sh -c 'uname -s 2>/dev/null || echo not')

INCLUDES = mcersa.h array.h aes.h des.h md5.h sha1.h arcfour.h blowfish.h \
md2.h rot-13.h tiger.h oaep.h sha2.h

ifeq ($(OS),Darwin)
TARGET = libmcersa.dylib
SHARED = $(CC) -dynamiclib -fPIC -o $(TARGET) $(OBJECTS) -lz
NAME1 = libmcersa.1.dylib
NAME2 = libmcersa.1.0.dylib
LINKS = ln -sf /usr/local/lib/$(TARGET) /usr/local/lib/$(NAME1) ; ln -sf /usr/local/lib/$(TARGET) /usr/local/lib/$(NAME2)
else
ifeq ($(OS),Fiwix)
TARGET = libmcersa.a
SHARED = ar rcs -o $(TARGET) $(OBJECTS)
LINKS = 
else
TARGET = libmcersa.so.1.0.0
SHARED = $(CC) -shared -fPIC -Wl,-soname,libmcersa.so.1 -o $(TARGET) $(OBJECTS)
NAME1 = libmcersa.so.1
NAME2 = libmcersa.so
LINKS = ln -sf /usr/local/lib/$(TARGET) /usr/local/lib/$(NAME1) ; ln -sf /usr/local/lib/$(TARGET) /usr/local/lib/$(NAME2)
endif
endif

$(TARGET): $(OBJECTS)
	$(SHARED)

install: $(TARGET)
	mkdir -p /usr/local/include/mce/
	mkdir -p /usr/local/lib
	cp $(INCLUDES) /usr/local/include/mce/
	cp $(TARGET) /usr/local/lib/
	$(LINKS)

clean:
	rm -f $(OBJECTS) $(TARGET)
