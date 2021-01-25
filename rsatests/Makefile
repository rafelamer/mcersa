OS = $(shell sh -c 'uname -s 2>/dev/null || echo not')
ifeq ($(OS),Minix)
CC = clang
 = -g -I. -I/usr/local/include
LIBS = -L/usr/local/lib -lmcersa -lz
else
CC = gcc
 = -g -I.
LIBS = -lmcersa -lz
endif

TARGETS = test00 test01 test02 test03 test04 test05 test06 test07 test08 test09 \
	test10 test11 test12 test13 test14 test15 test16 test17

all:
	$(CC) $() -o test00 test00.c $(LIBS)
	$(CC) $() -o test01 test01.c $(LIBS)
	$(CC) $() -o test02 test02.c $(LIBS)
	$(CC) $() -o test03 test03.c $(LIBS)
	$(CC) $() -o test04 test04.c $(LIBS)
	$(CC) $() -o test05 test05.c $(LIBS)
	$(CC) $() -o test06 test06.c $(LIBS)
	$(CC) $() -o test07 test07.c $(LIBS)
	$(CC) $() -o test08 test08.c $(LIBS)
	$(CC) $() -o test09 test09.c $(LIBS)
	$(CC) $() -o test10 test10.c $(LIBS)
	$(CC) $() -o test11 test11.c $(LIBS)
	$(CC) $() -o test12 test12.c $(LIBS)
	$(CC) $() -o test13 test13.c $(LIBS)
	$(CC) $() -o test14 test14.c $(LIBS)
	$(CC) $() -o test15 test15.c $(LIBS)
	$(CC) $() -o test16 test16.c $(LIBS)
	$(CC) $() -o test17 test17.c $(LIBS)


clean:
	rm -f $(TARGETS) mce.key mce.pub crmce.key crmce.pub
