/**************************************************************************************
* Filename:   random.c
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
#include <stdlib.h>

BD spRandomBD(size_t nbytes)
{
	BD n;
	FILE *fp;
	size_t ndigits;

	ndigits = (nbytes + BYTES_PER_DIGIT - 1) / BYTES_PER_DIGIT;
	if ((n = spInitWithAllocBD(ndigits)) == NULL)
		return NULL;

	if ((fp = fopen("/dev/urandom", "r")) == NULL)
	  {
		  freeBD(n);
		  return NULL;
	  }
	if (fread(n->digits, sizeof(unsigned char), nbytes, fp) != nbytes)
	  {
		  freeBD(n);
		  fclose(fp);
		  return NULL;
	  }
	n->used = ndigits;
	fclose(fp);
	return n;
}

unsigned char *randomBytes(size_t nbytes)
{
	FILE *fp;
	unsigned char *r;
	r = NULL;

	if ((fp = fopen("/dev/urandom", "r")) == NULL)
		return NULL;

	if ((r =
	     (unsigned char *)malloc(nbytes * sizeof(unsigned char))) == NULL)
	  {
		  fclose(fp);
		  return NULL;
	  }
	if (fread(r, sizeof(unsigned char), nbytes, fp) != nbytes)
	  {
		  free(r);
		  fclose(fp);
		  return NULL;
	  }
	return r;
}

uint8_t randomBytesToBuffer(unsigned char *buffer, size_t nbytes)
{
	FILE *fp;

	if ((fp = fopen("/dev/urandom", "r")) == NULL)
		return 0;
	if (fread(buffer, sizeof(unsigned char), nbytes, fp) != nbytes)
		return 0;
	return 1;
}

uint8_t getRandomSalt(unsigned char *salt)
{
	FILE *fp;
	unsigned char bs[16];
	size_t i;
	static const unsigned char map[17] = "0123456789ABCDEF";

	if ((fp = fopen("/dev/urandom", "r")) == NULL)
		return 0;
	if (fread(bs, sizeof(unsigned char), 16, fp) != 16)
	  {
		  fclose(fp);
		  return 0;
	  }
	fclose(fp);
	for (i = 0; i < 16; i++)
	  {
		  salt[2 * i] = map[(bs[i] >> 4) & 0x0f];
		  salt[2 * i + 1] = map[(bs[i]) & 0x0f];
	  }
	salt[32] = '\0';
	return 1;
}
