CFLAGS = -O3 -I.
CC = gcc

TARGETS = aes_test des_test md5_test sha1_test arcfour_test \
	blowfish_test md2_test rot-13_test sha256_test \
	tiger_test oaep_test zlib_test aes_encrypt_file \
	pkcs5_pbkdf2_test

all:
	$(CC) $(CFLAGS) -o aes_test aes_test.c -lmcersa -lz
	$(CC) $(CFLAGS) -o des_test des_test.c -lmcersa -lz
	$(CC) $(CFLAGS) -o sha1_test sha1_test.c -lmcersa -lz
	$(CC) $(CFLAGS) -o md5_test md5_test.c -lmcersa -lz
	$(CC) $(CFLAGS) -o blowfish_test blowfish_test.c -lmcersa -lz
	$(CC) $(CFLAGS) -o arcfour_test arcfour_test.c -lmcersa -lz
	$(CC) $(CFLAGS) -o md2_test md2_test.c -lmcersa -lz
	$(CC) $(CFLAGS) -o rot-13_test rot-13_test.c -lmcersa -lz
	$(CC) $(CFLAGS) -o sha256_test sha256_test.c -lmcersa -lz
	$(CC) $(CFLAGS) -o tiger_test tiger_test.c -lmcersa -lz
	$(CC) $(CFLAGS) -o oaep_test oaep_test.c -lmcersa -lz
	$(CC) $(CFLAGS) -o zlib_test zlib_test.c -lmcersa -lz
	$(CC) $(CFLAGS) -o aes_encrypt_file aes_encrypt_file.c -lmcersa -lz
	$(CC) $(CFLAGS) -o pkcs5_pbkdf2_test pkcs5_pbkdf2_test.c -lmcersa -lz

clean:
	rm -f $(TARGETS)

