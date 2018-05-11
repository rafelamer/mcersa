/**************************************************************************************
* Filename:   encrypt.c
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
#include <oaep.h>
#include <stdlib.h>
#include <string.h>

BD publicEncryptRSA(PublicRSAKey rsa, BD m)
{
	BD c;

	c = NULL;
	if (spCompareAbsoluteValues(rsa->n, m) <= 0)
		return NULL;
	if ((c = bdModExponentialBD(m, rsa->ek, rsa->n)) == NULL)
		return NULL;
	return c;
}

BD publicEncryptOAEPRSA(PublicRSAKey rsa, BD m)
{
	BD c, p;
	size_t size, sizeEM, used, nbytes;
	unsigned char *hash, *dg, *EM;

	c = p = NULL;
	hash = EM = NULL;
	size = spBytesInBD(rsa->n) - 2 * hLen - 3;
	nbytes = spBytesInBD(m);

	if (nbytes > size)
		goto final;

	if ((hash =
	     (unsigned char *)calloc(size, sizeof(unsigned char))) == NULL)
		goto final;
	memset(hash, 0x00, size);
	dg = (unsigned char *)(m->digits);
	memcpy(hash, dg, nbytes);

	sizeEM = size + 2 * hLen + 2;
	if ((EM =
	     (unsigned char *)calloc(sizeEM, sizeof(unsigned char))) == NULL)
		goto final;

	if (oaep_encode(hash, size, sizeEM, LABEL_CLIENT, EM) < 0)
		goto final;

	used = (sizeEM + BYTES_PER_DIGIT - 1) / BYTES_PER_DIGIT;
	if ((p = spInitWithAllocBD(used)) == NULL)
		goto final;
	dg = (unsigned char *)(p->digits);
	memcpy(dg, EM, sizeEM);
	p->used = used;

	if ((c = publicEncryptRSA(rsa, p)) == NULL)
		goto final;

 final:
	freeString(hash);
	freeBD(p);

	return c;
}

BD privateEncryptOAEPRSA(PrivateRSAKey rsa, BD m)
{
	BD c, p;
	size_t size, sizeEM, used, nbytes;
	unsigned char *hash, *dg, *EM;

	c = p = NULL;
	hash = EM = NULL;
	size = spBytesInBD(rsa->pub->n) - 2 * hLen - 3;
	nbytes = spBytesInBD(m);

	if (nbytes > size)
		goto final;

	if ((hash =
	     (unsigned char *)calloc(size, sizeof(unsigned char))) == NULL)
		goto final;
	memset(hash, 0x00, size);
	dg = (unsigned char *)(m->digits);
	memcpy(hash, dg, nbytes);

	sizeEM = size + 2 * hLen + 2;
	if ((EM =
	     (unsigned char *)calloc(sizeEM, sizeof(unsigned char))) == NULL)
		goto final;

	if (oaep_encode(hash, size, sizeEM, LABEL_CLIENT, EM) < 0)
		goto final;

	used = (sizeEM + BYTES_PER_DIGIT - 1) / BYTES_PER_DIGIT;
	if ((p = spInitWithAllocBD(used)) == NULL)
		goto final;
	dg = (unsigned char *)(p->digits);
	memcpy(dg, EM, sizeEM);
	p->used = used;

	if ((c = privateDecryptRSA(rsa, p)) == NULL)
		goto final;

 final:
	freeString(hash);
	freeString(EM);
	freeBD(p);

	return c;
}
