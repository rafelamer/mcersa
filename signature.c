/**************************************************************************************
* Filename:   signature.c
* Author:     Rafel Amer (rafel.amer AT upc.edu)
* Copyright:  Rafel Amer 2018
* Disclaimer: This code is presented "as is" and it has been written to 
*             implement the RSA encryption and decryption algorithm for 
*             educational purposes and should not be used in contexts that 
*             need cryptographically secure implementation
*	    
* License:    This library  is free software; you can redistribute it and/or
*             modify it under the terms of either:
*
*             1 the GNU Lesser General Public License as published by the Free
*               Software Foundation; either version 3 of the License, or (at your
*               option) any later version.
*
*             or
*
*             2 the GNU General Public License as published by the Free Software
*               Foundation; either version 2 of the License, or (at your option)
*               any later version.
*
*	      See https://www.gnu.org/licenses/
***************************************************************************************/
#include <mcersa.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sha2.h>

int signStackRSA(Stack st,PrivateRSAKey rsa,char *filename,uint8_t mode)
{
	size_t ndigits, nbytes, alloc;
	unsigned char *text;
	unsigned char digest[SHA512_DIGEST_SIZE];
	int ret;
	BD m, c;

	ret = SIGNATURE_ERROR;
	m = c = NULL;
	text = NULL;
	if ((st == NULL) || (st->data == NULL) || (st->used == 0))
		goto final;

	if (mode & STACKCOMPRESS)
	{
		if ((text = zlib_compress_data(st->data,st->used,&nbytes,&alloc)) == NULL)
			goto final;
		stSetDataInStack(st, text, nbytes, alloc);
		text = NULL;
	}
	nbytes = st->used;
	sha512(st->data,nbytes,digest);

	if ((text = (unsigned char *)malloc(nbytes * sizeof(unsigned char))) == NULL)
		goto final;
	memcpy(text,st->data,nbytes);

	if (! stReInitStackWithSize(st, nbytes + 1024))
		goto final;

	if (! stWriteOctetString(st,text,nbytes))
		goto final;
	freeString(text);

	if (! stWriteOctetString(st,filename,strlen(filename)))
		goto final;

	ndigits = (SHA512_DIGEST_SIZE + BYTES_PER_DIGIT - 1) / BYTES_PER_DIGIT;
	if ((m = spInitWithAllocBD(ndigits)) == NULL)
		goto final;
	m->used = ndigits;
	memcpy((void *)(m->digits),digest,SHA512_DIGEST_SIZE);
	if ((c = privateEncryptOAEPRSA(rsa, m)) == NULL)
		goto final;
	freeBD(m);

	if (! stWriteBD(st, c))
		goto final;

	if (! stWriteStartSequence(st))
		goto final;

	if (mode & STACKENCODE)
	{
		if ((text = b64_encode(st->data, st->used, &nbytes)) == NULL)
			goto final;
		stSetDataInStack(st,text,nbytes,nbytes);
		text = NULL;
	}

	ret = SIGNATURE_OK;	
 
 final:
 	freeString(text);
 	freeBD(m);
 	freeBD(c);
 	return ret;
}

int verifyAndExtractStackRSA(Stack st,PublicRSAKey rsa,uint8_t mode)
{
	size_t nbytes, length;
	unsigned char *text, *s;
	char *filename;
	unsigned char digest[2 * SHA512_DIGEST_SIZE];
	int ret, error;
	BD m, c;

	ret = SIGNATURE_ERROR;
	m = c = NULL;
	text = s = NULL;
	filename = NULL;
	if ((st == NULL) || (st->data == NULL) || (st->used == 0))
		goto final;

	if (mode & STACKENCODE)
	{
		if ((text = b64_decode(st->data, st->used, &nbytes)) == NULL)
			goto final;
		stSetDataInStack(st, text, nbytes, nbytes);
		text = NULL;
	}

	length = stReadStartSequenceAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto final;
	if (length != stBytesRemaining(st))
		goto final;

	if (((c = stReadBD(st, &error)) == NULL) || (error != 0))
		goto final;
	if ((m = publicDecryptOAEPRSA(rsa, c)) == NULL) {
		ret = SIGNATURE_BAD;
		goto final;
	}
	freeBD(c);

	memcpy(digest,m->digits,SHA512_DIGEST_SIZE);

	if ((s = stReadOctetString(st, &length, &error)) == NULL)
		goto final;
	if ((length == 0) || (error != 0))
		goto final;
	if ((filename = (char *)malloc((length + 1) * sizeof(char))) == NULL)
		goto final;
	memcpy(filename,s,length);
	filename[length] = '\0';

	if ((text = stReadOctetString(st, &length, &error)) == NULL)
		goto final;
	if ((length == 0) || (error != 0))
		goto final;

	sha512(text,length,digest + SHA512_DIGEST_SIZE);

	if (strncmp(digest,digest + SHA512_DIGEST_SIZE,SHA512_DIGEST_SIZE) != 0)
	{
		ret = SIGNATURE_BAD;
		goto final;
	}

	stSetDataInStack(st, text, length, length);
	text = NULL;

	if (mode & STACKCOMPRESS)
	{
		if ((text = zlib_uncompress_data(st->data,st->used,&nbytes,&length)) == NULL)
			goto final;	
		stSetDataInStack(st, text, nbytes, length);
		text = NULL;
	}


	int fd;
	if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR)) < 0) 
	{
		ret = SIGNATURE_OPEN_FILE_ERROR;
		goto final;
	}
	if (write(fd, st->data, st->used) != st->used)
	{
		ret = ENCRYPTION_WRITE_FILE_ERROR;
		goto final;
	}

	ret = SIGNATURE_OK;

 final:
 	freeString(text);
 	freeString(filename);
 	freeBD(m);
 	freeBD(c);
 	if (s != NULL)
 		free(s);
 	return ret;
}