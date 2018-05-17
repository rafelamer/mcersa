/**************************************************************************************
 * Filename:   cryptfiles.c
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

#define WRITEERROR {                    \
		close(fd);								 				  \
		unlink(*outfile);										\
		ret =  ENCRYPTION_WRITE_FILE_ERROR; \
		goto final;													\
	}

static const unsigned char baesf[] = "-----BEGIN AES ENCRYPTED FILE-----";
static const unsigned char eaesf[] = "-----END AES ENCRYPTED FILE-----";
static const unsigned char brsaf[] = "-----BEGIN RSA ENCRYPTED FILE-----";
static const unsigned char ersaf[] = "-----END RSA ENCRYPTED FILE-----";

int encryptFileWithAES(char *infile, char **outfile, int ascii)
{
	Stack st;
	unsigned char *text;
	unsigned char salt[33];
	size_t nbytes, alloc;
	int ret;
	uint8_t mode;

	st = NULL;
	ret = ENCRYPTION_ERROR;
	if (*outfile == NULL)
	{
		if((*outfile = (char *)calloc(strlen(infile) + 8,sizeof(char))) == NULL)
			goto final;
		if (ascii)
			sprintf(*outfile, "%s.asc", infile);
		else
			sprintf(*outfile, "%s.aes", infile);
	}
	/*
	   Initialize the Stack
	 */
	if ((st = stInitStack()) == NULL)
		goto final;
	/*
	   Read the file and store the data Stack
	 */
	if ((text = readFileBinaryMode(infile, &nbytes, &alloc)) == NULL)
	{
		ret = ENCRYPTION_FILE_NOT_FOUND;
		goto final;
	}
	stSetDataInStack(st, text, nbytes, alloc);
	text = NULL;
	/*
	   Get a random salt
	 */
	if (! getRandomSalt(salt))
		goto final;
	/*
	   Encrypt the Stack
	 */
	mode = STACKCOMPRESS + STACKSALT;
	if (ascii)
		mode += STACKENCODE;
	ret = encryptStackAES(st, NULL, salt, mode);
	if (ret != ENCRYPTION_OK)
		goto final;
	/*
	   Write the encrypted file
	 */
	int fd;
	if ((fd = open(*outfile, O_WRONLY | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR)) < 0)
	{
		ret = ENCRYPTION_OPEN_FILE_ERROR;
		goto final;
	}
	if (ascii)
	{
		size_t t;
		t = strlen((char *)baesf);
		if (write(fd, baesf, t) != t)
			WRITEERROR;
		if (write(fd, "\n", 1) != 1)
			WRITEERROR;
		if (write(fd, st->data, st->used) != st->used)
			WRITEERROR;
		t = strlen((char *)eaesf);
		if (write(fd, eaesf, t) != t)
			WRITEERROR;
		if (write(fd, "\n", 1) != 1)
			WRITEERROR;
		close(fd);
		ret = ENCRYPTION_OK;
		goto final;
	}
	if (write(fd, st->data, st->used) != st->used)
		WRITEERROR;

	ret = ENCRYPTION_OK;

final:
	freeStack(st);
	freeString(text);
	return ret;
}

int decryptFileWithAES(char *infile, char *outfile)
{
	Stack st;
	unsigned char *text, *begin;
	unsigned char salt[33];
	size_t nbytes, alloc, len;
	int ret;
	uint8_t mode;

	st = NULL;
	ret = ENCRYPTION_ERROR;
	/*
	   Read the file and store the data Stack
	 */
	if ((text = readFileBinaryMode(infile, &nbytes, &alloc)) == NULL)
	{
		ret = ENCRYPTION_FILE_NOT_FOUND;
		goto final;
	}
	if ((begin = clearCcommentsInText(text,baesf,eaesf)) != NULL)
	{
		len = strlen((char *)begin);
		if ((st = stInitStackWithSize(len + 128)) == NULL)
			goto final;
		memcpy(st->data, begin, len);
		st->used = len;
		mode = STACKENCODE;
		freeString(text);
	}
	else
	{
		if ((st = stInitStack()) == NULL)
			goto final;
		stSetDataInStack(st, text, nbytes, alloc);
		mode = 0;
		text = NULL;
	}
	mode += STACKCOMPRESS + STACKSALT;
	ret = decryptStackAES(st, NULL, salt, mode);
	if (ret != ENCRYPTION_OK)
		goto final;

	int fd;
	if ((fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR)) < 0)
	{
		ret = ENCRYPTION_OPEN_FILE_ERROR;
		goto final;
	}
	if (write(fd, st->data, st->used) != st->used)
	{
		close(fd);
		unlink(outfile);
		goto final;
	}

	close(fd);
	ret = ENCRYPTION_OK;

 final:
	freeStack(st);
	freeString(text);
	return ret;
}

int encryptFileWithRSA(char *infile, char **outfile, char *keyfile, int ascii)
{
	Stack st;
	unsigned char *text;
	size_t nbytes, alloc;
	int ret;
	uint8_t mode;
	PublicRSAKey rsa;

	st = NULL;
	rsa = NULL;
	ret = ENCRYPTION_ERROR;
	if (*outfile == NULL)
	{
		if((*outfile = (char *)calloc(strlen(infile) + 8,sizeof(char))) == NULL)
			goto final;
		if (ascii)
			sprintf(*outfile, "%s.asc", infile);
		else
			sprintf(*outfile, "%s.rsa", infile);
	}
	/*
	   Initialize the Stack
	*/
	if ((st = stInitStack()) == NULL)
		goto final;
	/*
		Read the public key file
	*/
	if ((rsa = bdReadPublicRSAKeyFromFile(keyfile)) == NULL)
	{
		ret = ENCRYPTION_PUBLIC_KEY_ERROR;
		goto final;
	}
	/*
		Read the file and store the data Stack
	*/
	if ((text = readFileBinaryMode(infile, &nbytes, &alloc)) == NULL)
	{
		ret = ENCRYPTION_FILE_NOT_FOUND;
		goto final;
	}
	stSetDataInStack(st, text, nbytes, alloc);
	text = NULL;
	/*
		Encrypt the Stack
	*/
	mode = STACKCOMPRESS;
	if (ascii)
		mode += STACKENCODE;
	ret = encryptStackAES(st, rsa, NULL, mode);
	if (ret != ENCRYPTION_OK)
		goto final;
	/*
		Write the encrypted file
	*/
	int fd;
	if ((fd = open(*outfile, O_WRONLY | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR)) < 0)
	{
		ret = ENCRYPTION_OPEN_FILE_ERROR;
		goto final;
	}
	if (ascii) {
		size_t t;
		t = strlen((char *)brsaf);
		if (write(fd, brsaf, t) != t)
			WRITEERROR;
		if (write(fd, "\n", 1) != 1)
			WRITEERROR;
		if (write(fd, st->data, st->used) != st->used)
			WRITEERROR;
		t = strlen((char *)ersaf);
		if (write(fd, ersaf, t) != t)
			WRITEERROR;
		if (write(fd, "\n", 1) != 1)
			WRITEERROR;
		close(fd);
		ret = ENCRYPTION_OK;
		goto final;
	}
	if (write(fd, st->data, st->used) != st->used)
		WRITEERROR;
	
	ret = ENCRYPTION_OK;
	
final:
	freeStack(st);
	freeString(text);
	freePublicRSAKey(rsa);
	return ret;
}

int decryptFileWithRSA(char *infile, char *outfile, char *keyfile)
{
	Stack st;
	unsigned char *text, *begin;
	size_t nbytes, alloc, len;
	int ret;
	uint8_t mode;
	PrivateRSAKey rsa;
	
	st = NULL;
	rsa = NULL;
	ret = ENCRYPTION_ERROR;
	/*
		Read the private key file
	*/
	if (((rsa = bdReadPrivateRSAKeyFromFile(keyfile)) == NULL) &&
	    ((rsa = bdReadEncryptedPrivateRSAKeyFromFile(keyfile)) == NULL))
	{
		ret = ENCRYPTION_PRIVATE_KEY_ERROR;
		goto final;
	}
	/*
		Read the file and store the data Stack
	*/
	if ((text = readFileBinaryMode(infile, &nbytes, &alloc)) == NULL) {
		ret = ENCRYPTION_FILE_NOT_FOUND;
		goto final;
	}
	if ((begin = clearCcommentsInText(text,brsaf,ersaf)) != NULL)
	{
		len = strlen((char *)begin);
		if ((st = stInitStackWithSize(len + 128)) == NULL)
			goto final;
		memcpy(st->data, begin, len);
		st->used = len;
		mode = STACKENCODE;
		freeString(text);
	}
	else
	{
		if ((st = stInitStack()) == NULL)
			goto final;
		stSetDataInStack(st, text, nbytes, alloc);
		mode = 0;
		text = NULL;
	}
	mode += STACKCOMPRESS;
	ret = decryptStackAES(st, rsa, NULL, mode);
	if (ret != ENCRYPTION_OK)
		goto final;
	
	int fd;
	if ((fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR)) < 0)
	{
		ret = ENCRYPTION_OPEN_FILE_ERROR;
		goto final;
	}
	if (write(fd, st->data, st->used) != st->used) {
		close(fd);
		unlink(outfile);
		goto final;
	}
	
	close(fd);
	ret = ENCRYPTION_OK;
	
final:
	freeStack(st);
	freeString(text);
	return ret;
}

