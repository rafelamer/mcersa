/**************************************************************************************
* Filename:   rsafiles.c
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
#include <array.h>
#include <unistd.h>
#include <fcntl.h>
#include <aes.h>

static const char brpk[] = "-----BEGIN RSA PRIVATE KEY-----";
static const char erpk[] = "-----END RSA PRIVATE KEY-----";
static const char bpk[] = "-----BEGIN PRIVATE KEY-----";
static const char epk[] = "-----END PRIVATE KEY-----";
static const char bpubk[] = "-----BEGIN PUBLIC KEY-----";
static const char epubk[] = "-----END PUBLIC KEY-----";

#define READ_BD_FROM_STACK(n)     n = stReadBD(st,&error);     \
    if ((n == NULL) || (error != 0))                           \
        goto errorREAD;

#define WRITEERROR     { \
     close(fd);          \
     unlink(filename);   \
     goto final;         \
  }

static unsigned char *clear_rsa_private_comments(const unsigned char *string)
{
	unsigned char *begin, *end;
	if ((begin = (unsigned char *)strstr((char *)string, brpk)) != NULL)
	  {
		  begin += strlen(brpk);
		  if (*begin == '\n')
			  begin++;
		  if ((end =
		       (unsigned char *)strstr((char *)begin, erpk)) == NULL)
			  return NULL;
		  *end = '\0';
		  return begin;
	  }
	if ((begin = (unsigned char *)strstr((char *)string, bpk)) == NULL)
		return NULL;
	begin += strlen(bpk);
	if (*begin == '\n')
		begin++;
	if ((end = (unsigned char *)strstr((char *)begin, epk)) == NULL)
		return NULL;
	*end = '\0';
	return begin;
}

static unsigned char *clear_rsa_public_comments(const unsigned char *string)
{
	unsigned char *begin, *end;
	if ((begin = (unsigned char *)strstr((char *)string, bpubk)) == NULL)
		return NULL;
	begin += strlen(bpubk);
	if (*begin == '\n')
		begin++;
	if ((end = (unsigned char *)strstr((char *)begin, epubk)) == NULL)
		return NULL;
	*end = '\0';
	return begin;
}

static unsigned char *clear_rsa_private_info(const unsigned char *string,
					     unsigned char *salt)
{
	unsigned char *begin, *end;
	size_t i;

	if ((begin = (unsigned char *)strstr((char *)string, brpk)) == NULL)
		return NULL;

	begin += strlen(brpk);
	while (*begin == '\n')
		begin++;

	if (strncmp((char *)begin, "Proc-Type: 4,ENCRYPTED", 22) != 0)
		return NULL;
	begin += 22;
	while (*begin == '\n')
		begin++;

	if (strncmp((char *)begin, "DEK-Info: AES-256-CBC,", 22) != 0)
		return NULL;
	begin += 22;
	if (strlen((char *)begin) < 32)
		return NULL;
	for (i = 0; i < 32; i++)
		salt[i] = *begin++;
	salt[32] = '\0';
	while (*begin == '\n')
		begin++;

	if ((end = (unsigned char *)strstr((char *)begin, erpk)) == NULL)
		return NULL;
	*end = '\0';
	return begin;
}

static Stack bdWritePrivateRSAKeyToStack(PrivateRSAKey rsa)
{
	Stack st;

	st = NULL;
	if ((st = stInitStackWithSize(2048)) == NULL)
		goto final;
	/*
	   Sequence of integers
	 */
	if (!stWriteBD(st, rsa->c2))
		goto final;
	if (!stWriteBD(st, rsa->kq))
		goto final;
	if (!stWriteBD(st, rsa->kp))
		goto final;
	if (!stWriteBD(st, rsa->q))
		goto final;
	if (!stWriteBD(st, rsa->p))
		goto final;
	if (!stWriteBD(st, rsa->dk))
		goto final;
	if (!stWriteBD(st, rsa->pub->ek))
		goto final;
	if (!stWriteBD(st, rsa->pub->n))
		goto final;
	/*
	   Zero integer
	 */
	if (!stWriteInteger(st, 0))
		goto final;
	/*
	   Length of integers and sequence
	 */
	if (!stWriteStartSequence(st))
		goto final;
	/*
	   Length and OCTET STRING
	 */
	if (!stWriteStartOctetString(st))
		goto final;
	/*
	   Object rsaEncryption identifier
	 */
	if (!stWriteRsaEncryptionOI(st))
		goto final;
	/*
	   Zero integer
	 */
	if (!stWriteInteger(st, 0))
		goto final;
	/*
	   Total length and sequence
	 */
	if (!stWriteStartSequence(st))
		goto final;

	return st;

 final:
	freeStack(st);
	return NULL;
}

uint8_t bdWritePrivateRSAKeyToFile(const char *filename, PrivateRSAKey rsa)
{
	Stack st;
	uint8_t r;
	unsigned char *b64data;

	r = 0;
	st = NULL;
	b64data = NULL;
	if ((st = bdWritePrivateRSAKeyToStack(rsa)) == NULL)
		goto final;

	/*
	   Encode the data with base64
	 */
	size_t outlen;
	int fd;
	if ((b64data = b64_encode(st->data, st->used, &outlen)) == NULL)
		goto final;
	/*
	   Write to a file
	 */
	if ((fd =
	     open(filename, O_WRONLY | O_CREAT | O_TRUNC,
		  S_IRUSR | S_IWUSR)) < 0)
		goto final;

	size_t t;
	t = strlen(bpk);
	if (write(fd, bpk, t) != t)
		WRITEERROR;
	if (write(fd, "\n", 1) != 1)
		WRITEERROR;
	if (write(fd, b64data, outlen) != outlen)
		WRITEERROR;
	t = strlen(epk);
	if (write(fd, epk, t) != t)
		WRITEERROR;
	if (write(fd, "\n", 1) != 1)
		WRITEERROR;
	close(fd);
	r = 1;

 final:
	freeString(b64data);
	freeStack(st);
	return r;
}

uint8_t bdWriteEncryptedPrivateRSAKeyToFile(const char *filename,
					    PrivateRSAKey rsa)
{
	Stack st;
	unsigned char salt[33];
	const char enc[] = "\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,";
	uint8_t ret;

	ret = 0;
	if ((st = bdWritePrivateRSAKeyToStack(rsa)) == NULL)
		goto final;
	if (!getRandomSalt(salt))
		goto final;
#if 0
	SAVEDEBUG("debug/rsa.bin", st->data, st->used);
#endif
	if (encryptStackAES(st, NULL, salt, STACKENCODE) != ENCRYPTION_OK)
		goto final;

	/*
	   Write to a file
	 */
	int fd;
	size_t t;
	if ((fd =
	     open(filename, O_WRONLY | O_CREAT | O_TRUNC,
		  S_IRUSR | S_IWUSR)) < 0)
		goto final;

	t = strlen(brpk);
	if (write(fd, brpk, t) != t)
		WRITEERROR;
	t = strlen(enc);
	if (write(fd, enc, t) != t)
		WRITEERROR;
	t = strlen((char *)salt);
	if (write(fd, salt, t) != t)
		WRITEERROR;
	if (write(fd, "\n\n", 2) != 2)
		WRITEERROR;
	if (write(fd, st->data, st->used) != st->used)
		WRITEERROR;
	t = strlen(erpk);
	if (write(fd, erpk, t) != t)
		WRITEERROR;
	if (write(fd, "\n", 1) != 1)
		WRITEERROR;
	close(fd);

	ret = 1;

 final:
	freeStack(st);
	return ret;
}

static PrivateRSAKey bdReadPrivateRSAKeyFromStack(Stack st)
{
	PrivateRSAKey rsa;
	rsa = NULL;
	/*
	   Initialize the rsa variable
	 */
	if ((rsa = bdInitRSAPrivateKey()) == NULL)
		goto errorREAD;

	/*
	   Read the data from the stack
	 */
	size_t length;
	int error;
	unsigned long long integer;

	length = stReadStartSequenceAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto errorREAD;

	if (length != stBytesRemaining(st))
		goto errorREAD;

	integer = stReadInteger(st, &error);
	if ((integer != 0) || (error != 0))
		goto errorREAD;

	if (stReadOptionalRsaEncryptionOI(st) == 1)
	  {
		  length = stReadStartOctetStringAndLength(st, &error);
		  if ((length == 0) || (error != 0))
			  goto errorREAD;

		  length = stReadStartSequenceAndLength(st, &error);
		  if ((length == 0) || (error != 0))
			  goto errorREAD;

		  integer = stReadInteger(st, &error);
		  if ((integer != 0) || (error != 0))
			  goto errorREAD;
	  }
	READ_BD_FROM_STACK(rsa->pub->n);
	READ_BD_FROM_STACK(rsa->pub->ek);
	READ_BD_FROM_STACK(rsa->dk);
	READ_BD_FROM_STACK(rsa->p);
	READ_BD_FROM_STACK(rsa->q);
	READ_BD_FROM_STACK(rsa->kp);
	READ_BD_FROM_STACK(rsa->kq);
	READ_BD_FROM_STACK(rsa->c2);

	return rsa;

 errorREAD:
	freePrivateRSAKey(rsa);
	return NULL;
}

PrivateRSAKey bdReadPrivateRSAKeyFromFile(const char *filename)
{
	unsigned char *str, *begin, *der;
	size_t len, outlen, alloc;
	Stack st;
	PrivateRSAKey rsa;
	int ok;

	rsa = NULL;
	st = NULL;
	str = der = NULL;
	ok = 0;
	if ((str = readFileBinaryMode(filename, &len, &alloc)) == NULL)
		return NULL;
	if (len == 0)
		goto final;

	/*
	   Clear begin and end comments
	 */

	if ((begin = clear_rsa_private_comments(str)) == NULL)
		goto final;
	len = strlen((char *)begin);

	/*
	   Decode the data with base64
	   Initialize the stack and copy data
	 */
	if ((der = b64_decode((unsigned char *)begin, len, &outlen)) == NULL)
		goto final;

	if ((st = stInitStackWithSize(outlen + 512)) == NULL)
		goto final;
	memcpy(st->data, der, outlen);
	st->used = outlen;

	if ((rsa = bdReadPrivateRSAKeyFromStack(st)) == NULL)
		goto final;

	ok = 1;

 final:
	if (!ok)
	  {
		  freePrivateRSAKey(rsa);
		  rsa = NULL;
	  }
	freeStack(st);
	freeString(str);
	freeString(der);
	return rsa;
}

PrivateRSAKey bdReadEncryptedPrivateRSAKeyFromFile(const char *filename)
{
	unsigned char *begin, *text;
	unsigned char salt[33];
	size_t nbytes, alloc;
	Stack st;
	PrivateRSAKey rsa;
	int ok;

	rsa = NULL;
	st = NULL;
	text = NULL;
	ok = 0;
	if ((text = readFileBinaryMode(filename, &nbytes, &alloc)) == NULL)
		goto final;
	if (nbytes == 0)
		goto final;

	if ((begin = clear_rsa_private_info(text, salt)) == NULL)
		goto final;
	nbytes = strlen((char *)begin);

	if ((st = stInitStackWithSize(nbytes + 512)) == NULL)
		goto final;
	memcpy(st->data, begin, nbytes);
	st->used = nbytes;
	freeString(text);

	if (decryptStackAES(st, NULL, salt, STACKENCODE) != ENCRYPTION_OK)
		goto final;

	if ((rsa = bdReadPrivateRSAKeyFromStack(st)) == NULL)
		goto final;

	ok = 1;

 final:
	if (!ok)
	  {
		  freePrivateRSAKey(rsa);
		  rsa = NULL;
	  }
	freeStack(st);
	freeString(text);
	return rsa;
}

PublicRSAKey bdReadPublicRSAKeyFromFile(const char *filename)
{
	unsigned char *str, *begin, *der;
	size_t len, outlen, alloc;
	Stack st;
	PublicRSAKey rsa;

	rsa = NULL;
	st = NULL;
	str = der = NULL;
	if ((str = readFileBinaryMode(filename, &len, &alloc)) == NULL)
		return NULL;
	if (len == 0)
		goto errorREAD;

	/*
	   Clear begin and end comments
	 */

	if ((begin = clear_rsa_public_comments(str)) == NULL)
		goto errorREAD;
	len = strlen((char *)begin);

	/*
	   Decode the data with base64
	   Initialize the stack and copy data
	 */
	if ((der = b64_decode((unsigned char *)begin, len, &outlen)) == NULL)
		goto errorREAD;

	if ((st = stInitStackWithSize(outlen + 512)) == NULL)
		goto errorREAD;
	memcpy(st->data, der, outlen);
	st->used = outlen;
	freeString(der);
	freeString(str);

	if ((rsa = bdInitRSAPublicKey()) == NULL)
		goto errorREAD;

	/*
	   Read the data from the stack
	 */
	size_t length;
	int error;

	length = stReadStartSequenceAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto errorREAD;

	error = stReadOptionalRsaEncryptionOI(st);

	length = stReadStartBitStringAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto errorREAD;

	while (*(st->read) != 0x30)
		st->read++;

	length = stReadStartSequenceAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto errorREAD;

	READ_BD_FROM_STACK(rsa->n);
	READ_BD_FROM_STACK(rsa->ek);

	return rsa;

 errorREAD:
	freePublicRSAKey(rsa);
	freeString(str);
	freeString(der);
	return NULL;
}

uint8_t bdWritePublicRSAKeyToFile(const char *filename, PublicRSAKey rsa)
{
	unsigned char *b64data;
	uint8_t r;
	Stack st;

	st = NULL;
	b64data = NULL;
	r = 0;
	if ((st = stInitStackWithSize(2048)) == NULL)
		goto final;

	/*
	   Sequence of integers
	 */
	if (!stWriteBD(st, rsa->ek))
		goto final;
	if (!stWriteBD(st, rsa->n))
		goto final;

	/*
	   Length of integers and sequence
	 */
	if (!stWriteStartSequence(st))
		goto final;

	/*
	   Length and BIT STRING
	 */
	if (!stWriteStartBitString(st))
		goto final;

	/*
	   Object rsaEncryption identifier
	 */
	if (!stWriteRsaEncryptionOI(st))
		goto final;

	/*
	   Length of data and SEQUENCE
	 */
	if (!stWriteStartSequence(st))
		goto final;

	/*
	   Encode the data with base64
	 */
	size_t outlen;
	int fd;

	if ((b64data = b64_encode(st->data, st->used, &outlen)) == NULL)
		goto final;

	/*
	   Write to a file
	 */
	if ((fd =
	     open(filename, O_WRONLY | O_CREAT | O_TRUNC,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0)
		goto final;

	size_t t;
	t = strlen(bpubk);
	if (write(fd, bpubk, t) != t)
		WRITEERROR;
	if (write(fd, "\n", 1) != 1)
		WRITEERROR;
	if (write(fd, b64data, outlen) != outlen)
		WRITEERROR;
	t = strlen(epubk);
	if (write(fd, epubk, t) != t)
		WRITEERROR;
	if (write(fd, "\n", 1) != 1)
		WRITEERROR;
	close(fd);
	r = 1;

 final:
	freeString(b64data);
	freeStack(st);
	return r;
}
