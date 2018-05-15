/**************************************************************************************
* Filename:   decrypt.c
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

BD privateDecryptRSA(PrivateRSAKey rsa, BD c)
/*
  m = c^dk mod (n)

  But, it can be computed as follows

  m1 = c^kp mod (p)
  m2 = c^kq mod(q)
  h = (m1 - m2)*c2 mod(p)
  m = m2 + q * h
*/
{
	BD m, m1, m2, h;
	int r = 0;

	m = m1 = m2 = h = NULL;
	if (spCompareAbsoluteValues(rsa->pub->n, c) <= 0)
		goto final;

	if ((m1 = bdModExponentialBD(c, rsa->kp, rsa->p)) == NULL)
		goto final;
	if ((m2 = bdModExponentialBD(c, rsa->kq, rsa->q)) == NULL)
		goto final;
	if ((m = bdSubtractBD(m1, m2)) == NULL)
		goto final;
	if ((h = bdModularBD(m, rsa->p)) == NULL)
		goto final;
	freeBD(m);
	if ((m = bdMultiplyAndModularBD(h, rsa->c2, rsa->p)) == NULL)
		goto final;
	if (bdMultiplyBDBy(&m, rsa->q) == 0)
		goto final;
	bdAddAbsoluteValueTo(m, m2);
	r = 1;

final:
	freeBD(m1);
	freeBD(m2);
	freeBD(h);
	if (r == 0)
		freeBD(m);
	return m;
}

BD privateDecryptOAEPRSA(PrivateRSAKey rsa, BD c)
{
	BD p, m;
	unsigned char *dg, *EM;
	size_t size, sizeEM, used, nbytes;

	p = m = NULL;
	dg = EM = NULL;
	if ((p = privateDecryptRSA(rsa, c)) == NULL)
		goto final;

	size = spBytesInBD(rsa->pub->n) - 2 * hLen - 3;
	sizeEM = spBytesInBD(rsa->pub->n) - 1;
	if ((EM = (unsigned char *)calloc(sizeEM, sizeof(unsigned char))) == NULL)
		goto final;

	dg = (unsigned char *)(p->digits);
	memcpy(EM, dg, sizeEM);

	if (oaep_decode(EM, sizeEM, LABEL_CLIENT) < 0)
		goto final;

	nbytes = size;
	dg = EM + sizeEM - 1;
	while (*dg-- == 0x00)
		nbytes--;
	used = (nbytes + BYTES_PER_DIGIT - 1) / BYTES_PER_DIGIT;
	if ((m = spInitWithAllocBD(used)) == NULL)
		goto final;

	dg = (unsigned char *)(m->digits);
	memcpy(dg, EM + (sizeEM - size), nbytes);
	m->used = used;

final:
	freeBD(p);
	freeString(EM);
	return m;
}

BD publicDecryptOAEPRSA(PublicRSAKey rsa, BD c)
{
	BD p, m;
	unsigned char *dg, *EM;
	size_t size, sizeEM, used, nbytes;

	p = m = NULL;
	dg = EM = NULL;
	if ((p = publicEncryptRSA(rsa, c)) == NULL)
		goto final;

	size = spBytesInBD(rsa->n) - 2 * hLen - 3;
	sizeEM = spBytesInBD(rsa->n) - 1;
	if ((EM =
	     (unsigned char *)calloc(sizeEM, sizeof(unsigned char))) == NULL)
		goto final;

	dg = (unsigned char *)(p->digits);
	memcpy(EM, dg, sizeEM);

	if (oaep_decode(EM, sizeEM, LABEL_CLIENT) < 0)
		goto final;

	nbytes = size;
	dg = EM + sizeEM - 1;
	while (*dg-- == 0x00)
		nbytes--;
	used = (nbytes + BYTES_PER_DIGIT - 1) / BYTES_PER_DIGIT;
	if ((m = spInitWithAllocBD(used)) == NULL)
		goto final;

	dg = (unsigned char *)(m->digits);
	memcpy(dg, EM + (sizeEM - size), nbytes);
	m->used = used;

final:
	freeBD(p);
	freeString(EM);
	return m;
}
