#include <mce/mcersa.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	unsigned char *text, *ztext, *rtext;
	size_t nbytes, alloc, znbytes, rnbytes, zalloc;
	int ret;

	ret = EXIT_FAILURE;
	text = ztext = rtext = NULL;
	/*
	   Read the file to memory
	 */
	if ((text = readFileBinaryMode("Lion.jpg", &nbytes, &alloc)) == NULL)
		goto final;

	printf("Bytes read: %lu\n", nbytes);

	if ((ztext =
	     zlib_compress_data(text, nbytes, &znbytes, &zalloc)) == NULL)
		goto final;

	printf("Compressed size: %lu. Allocated size: %lu\n", znbytes, zalloc);

	if ((rtext =
	     zlib_uncompress_data(ztext, znbytes, &rnbytes, &zalloc)) == NULL)
		goto final;

	if (nbytes != rnbytes)
		goto final;

	if (memcmp(text, rtext, nbytes) != 0)
		goto final;

	printf("Uncompressed size: %lu. Allocated size: %lu\n", nbytes, zalloc);

	ret = EXIT_SUCCESS;

 final:
	if (text != NULL)
		free(text);
	if (ztext != NULL)
		free(ztext);
	if (rtext != NULL)
		free(rtext);

	if (ret == EXIT_FAILURE)
		printf("Error compressing or decompressing the file\n");
	else
		printf("Compression and decompression OK\n");

	return ret;
}
