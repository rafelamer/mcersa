/**************************************************************************************
* Filename:   cryptaes.c
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
#include <aes.h>

int encryptStackAES(Stack st, PublicRSAKey rsa, unsigned char *salt,
		    uint8_t mode)
{
	char *passphrase;
	size_t nblocks, nbytes, alloc;
	unsigned char *text;
	unsigned int key_schedule[60];
	unsigned char keys[KEK_KEY_LEN];
	int ret;
	BD m, c;

	passphrase = NULL;
	text = NULL;
	m = c = NULL;
	ret = ENCRYPTION_ERROR;
	if ((st->data == NULL) || (st->used == 0))
		goto final;
	if ((rsa == NULL)
	    && ((passphrase = getAndVerifyPassphrase(10)) == NULL))
	  {
		  ret = ENCRYPTION_WRONG_PASSWORD;
		  goto final;
	  }

	/*
	   Compress
	 */
	if (mode & STACKCOMPRESS)
	  {
		  if ((text =
		       zlib_compress_data(st->data, st->used, &nbytes,
					  &alloc)) == NULL)
			  goto final;
		  stSetDataInStack(st, text, nbytes, alloc);
	  }

	/*
	   Encryption process
	   lbc is the length of the data before encrypt
	 */
	unsigned long long lbc;
	lbc = st->used;
	memset(st->data + st->used, 0, st->alloc - st->used);
	nblocks = (st->used + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
	if (st->alloc < nblocks * AES_BLOCK_SIZE)
	  {
		  size_t add = nblocks * AES_BLOCK_SIZE - st->alloc + 128;
		  if (!stExpandStackInSize(st, add))
			  goto final;
	  }
	/*
	   Compute the keys
	 */
	if (rsa == NULL)
	  {
		  if (pkcs5_pbkdf2
		      (passphrase, strlen(passphrase), salt,
		       strlen((char *)salt), keys, KEK_KEY_LEN, ITERATION) != 0)
			  goto final;
	} else
	  {
		  /*
		     We set random keys and we encrypt it with the public key
		   */
		  size_t ndigits;
		  if (!randomBytesToBuffer(keys, KEK_KEY_LEN))
			  goto final;
		  nbytes = KEK_KEY_LEN * sizeof(unsigned char);
		  ndigits = (nbytes + BYTES_PER_DIGIT - 1) / BYTES_PER_DIGIT;
		  if ((m = spInitWithAllocBD(ndigits)) == NULL)
			  goto final;
		  m->used = ndigits;
		  memcpy((void *)(m->digits), keys, nbytes);
		  if ((c = publicEncryptOAEPRSA(rsa, m)) == NULL)
			  goto final;
		  freeBD(m);
	  }
	/*
	   Encrypt
	 */
	aes_key_setup(keys, key_schedule, 256);
	if ((text =
	     (unsigned char *)malloc(nblocks * AES_BLOCK_SIZE *
				     sizeof(unsigned char))) == NULL)
		goto final;
	if (!aes_encrypt_cbc
	    (st->data, nblocks * AES_BLOCK_SIZE, text, key_schedule, 256,
	     keys + 32))
		goto final;
	memset(keys, 0, KEK_KEY_LEN);

#if 0
	SAVEDEBUG("debug/rsacrypt.bin", text, nblocks * AES_BLOCK_SIZE);
#endif
	if (!stReInitStackWithSize(st, nblocks * AES_BLOCK_SIZE + 1024))
		goto final;
	if (!stWriteOctetString(st, text, nblocks * AES_BLOCK_SIZE))
		goto final;
	freeString(text);

	if (!stWriteInteger(st, lbc))
		goto final;
	if (c != NULL)
		if (!stWriteBD(st, c))
			goto final;
	if (mode & STACKSALT)
		if (!stWriteOctetString(st, salt, strlen((char *)salt)))
			goto final;
	if (!stWriteStartSequence(st))
		goto final;
#if 0
	SAVEDEBUG("debug/rsacryptsequence.bin", st->data, st->used);
#endif
	/*
	   Encode to Base64
	 */
	if (mode & STACKENCODE)
	  {
		  if ((text = b64_encode(st->data, st->used, &nbytes)) == NULL)
			  goto final;
		  stSetDataInStack(st, text, nbytes, nbytes);
	  }
#if 0
	SAVEDEBUG("debug/rsacryptsequence64.bin", st->data, st->used);
#endif
	ret = ENCRYPTION_OK;

 final:
	freeString(passphrase);
	freeBD(m);
	freeBD(c);
	return ret;
}

int decryptStackAES(Stack st, PrivateRSAKey rsa, unsigned char *salt,
		    uint8_t mode)
{
	char *passphrase;
	size_t nbytes, nblocks, length;
	unsigned char *text, *s;
	unsigned int key_schedule[60];
	unsigned char keys[KEK_KEY_LEN];
	int ret, error;
	unsigned long long lbc;
	BD m, c;

	passphrase = NULL;
	text = s = NULL;
	m = c = NULL;
	ret = ENCRYPTION_ERROR;
	if ((st->data == NULL) || (st->used == 0))
		goto final;
#if 0
	SAVEDEBUG("debug/de-rsacryptsequence64.bin", st->data, st->used);
#endif
	/*
	   Decode from Base64
	 */
	if (mode & STACKENCODE)
	  {
		  if ((text = b64_decode(st->data, st->used, &nbytes)) == NULL)
			  goto final;
		  stSetDataInStack(st, text, nbytes, nbytes);
	  }
#if 0
	SAVEDEBUG("debug/de-rsacryptsequence.bin", st->data, st->used);
#endif
	/*
	   Decrypt the data
	 */
	length = stReadStartSequenceAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto final;
	if (length != stBytesRemaining(st))
		goto final;
	if (mode & STACKSALT)
	  {
		  if ((s = stReadOctetString(st, &length, &error)) == NULL)
			  goto final;
		  if ((length != 32) || (error != 0))
			  goto final;
		  memcpy(salt, s, 32);
		  salt[32] = '\0';
		  freeString(s);
	  }

	/*
	   If we are encrypted the data with a public key,
	   we read the encryption key from the Stack
	 */
	if (rsa != NULL)
	  {
		  if (((c = stReadBD(st, &error)) == NULL) || (error != 0))
			  goto final;
		  if ((m = privateDecryptOAEPRSA(rsa, c)) == NULL)
			  goto final;
		  freeBD(c);
		  memcpy(keys, m->digits, KEK_KEY_LEN);
	  }

	if (((lbc = stReadInteger(st, &error)) == 0) || (error != 0))
		goto final;

	if ((text = stReadOctetString(st, &length, &error)) == NULL)
		goto final;
	if ((length == 0) || (error != 0))
		goto final;
	stSetDataInStack(st, text, length, length);
#if 0
	SAVEDEBUG("debug/de-rsacrypt.bin", st->data, st->used);
#endif

	if (rsa == NULL)
	  {
		  if ((passphrase =
		       getPassword("Enter the decryption passphrase: ")) ==
		      NULL)
			  goto final;
		  if (pkcs5_pbkdf2
		      (passphrase, strlen(passphrase), salt,
		       strlen((char *)salt), keys, KEK_KEY_LEN, ITERATION) != 0)
			  goto final;
	  }
	nblocks = st->used / AES_BLOCK_SIZE;
	if ((text =
	     (unsigned char *)malloc(nblocks * AES_BLOCK_SIZE *
				     sizeof(unsigned char))) == NULL)
		goto final;
	aes_key_setup(keys, key_schedule, 256);
	aes_decrypt_cbc(st->data, nblocks * AES_BLOCK_SIZE, text, key_schedule,
			256, keys + 32);
	stSetDataInStack(st, text, lbc, nblocks * AES_BLOCK_SIZE);
#if 0
	SAVEDEBUG("debug/de-rsa.bin", st->data, st->used);
#endif

	/*
	   Uncompress
	 */
	if (mode & STACKCOMPRESS)
	  {
		  if ((text =
		       zlib_uncompress_data(st->data, st->used, &nbytes,
					    &length)) == NULL)
			  goto final;
		  stSetDataInStack(st, text, nbytes, length);
	  }

	ret = ENCRYPTION_OK;

 final:
	freeString(passphrase);
	freeString(s);
	freeBD(m);
	freeBD(c);
	return ret;
}
