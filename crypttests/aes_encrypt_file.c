#include <mce/mcersa.h>
#include <mce/aes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	char filename[] = "rfc3279.txt";
	unsigned char *text, *ztext, *cypher;
	size_t nbytes, alloc, znbytes, zalloc, nblocks;
	int ret;

	ret = EXIT_FAILURE;
	text = ztext = cypher = NULL;

	/*
	   Read the file to memory
	 */
	if ((text = readFileBinaryMode(filename, &nbytes, &alloc)) == NULL)
		goto final;

	printf("%lu bytes readed from file %s\n", nbytes, filename);

	/*
	   Compress it
	 */
	if ((ztext =
	     zlib_compress_data(text, nbytes, &znbytes, &zalloc)) == NULL)
		goto final;
	free(text);
	text = NULL;
	/*
	   Encrypting 
	 */
	unsigned int key_schedule[60];
	unsigned char key[32] =
	    { 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0x71, 0xbe,
0x2b, 0x73, 0xae, 0xf0, 0x85,
		0x7d, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
		    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca
	};

	unsigned char iv[16] =
	    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

	nblocks = (znbytes + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
	if (zalloc < nblocks * AES_BLOCK_SIZE)
	  {
		  zalloc = nblocks * AES_BLOCK_SIZE;
		  if ((ztext =
		       (unsigned char *)realloc(ztext,
						zalloc *
						sizeof(unsigned char))) == NULL)
			  goto final;
		  memset(ztext + znbytes, 0,
			 AES_BLOCK_SIZE - znbytes % AES_BLOCK_SIZE);
	  }

	aes_key_setup(key, key_schedule, 256);
	if ((cypher =
	     (unsigned char *)malloc(nblocks * AES_BLOCK_SIZE *
				     sizeof(unsigned char))) == NULL)
		goto final;

	aes_encrypt_cbc(ztext, nblocks * AES_BLOCK_SIZE, cypher, key_schedule,
			256, iv);

	/*
	   Decrypting
	 */
	memset(ztext, 0, zalloc);

	aes_decrypt_cbc(cypher, nblocks * AES_BLOCK_SIZE, ztext, key_schedule,
			256, iv);

	if ((text =
	     zlib_uncompress_data(ztext, znbytes, &nbytes, &alloc)) == NULL)
		goto final;

	printf
	    ("%lu bytes restored after compression-encryption and decryption-uncompression\n",
	     nbytes);

	ret = EXIT_SUCCESS;

 final:
	if (text != NULL)
		free(text);

	if (cypher != NULL)
		free(cypher);

	if (ztext != NULL)
		free(ztext);

	if (ret == EXIT_FAILURE)
		printf("Error reading or encrypting the file\n");
	return ret;
}
