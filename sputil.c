/**************************************************************************************
 * Filename:   sputil.c
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
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <sha2.h>

BD spAllocBD()
{
	BD n;
	if ((n = (BD) malloc(sizeof(big_digit))) == NULL)
		return NULL;
	n->digits = NULL;
	n->used = 0;
	n->alloc = 0;
	n->sign = 0;
	return n;
}

BD spInitBD()
{
	BD n;
	if ((n = (BD) malloc(sizeof(big_digit))) == NULL)
		return NULL;
	make_vector(n->digits, ALLOCSIZE);
	n->used = 0;
	n->alloc = ALLOCSIZE;
	n->sign = 1;
	return n;
}

BD spInitWithOneBD()
{
	BD n;
	if ((n = spInitBD()) == NULL)
		return NULL;
	n->used = 1;
	n->digits[0] = 1;
	return n;
}

BD spInitWithAllocBD(size_t alloc)
{
	BD n;
	if ((n = (BD) malloc(sizeof(big_digit))) == NULL)
		return NULL;
	make_vector(n->digits, alloc);
	n->used = 0;
	n->alloc = alloc;
	n->sign = 1;
	return n;
}

void spSetZeroBD(BD n)
{
	memset(n->digits, 0, n->used * sizeof(digit));
	n->used = 0;
}

void spAugmentDB(BD n)
{
	expand_vector(n->digits, n->alloc + ALLOCSIZE);
	memset(n->digits + n->alloc, 0, ALLOCSIZE * sizeof(digit));
	n->alloc += ALLOCSIZE;
}

void spAugmentInSizeDB(BD n, size_t ndigits)
{
	expand_vector(n->digits, n->alloc + ndigits);
	memset(n->digits + n->alloc, 0, ndigits * sizeof(digit));
	n->alloc += ndigits;
}

void spFreeBD(BD * n)
{
	if (*n != NULL)
	{
		if ((*n)->digits != NULL)
		{
			memset((void *)((*n)->digits),0,(*n)->used * BYTES_PER_DIGIT);
			free_vector((*n)->digits);
		}
		free(*n);
	}
	*n = NULL;
}

BD spCopyBD(BD n)
{
	BD m;
	if ((m = spAllocBD()) == NULL)
		return NULL;
	m->used = n->used;
	m->alloc = n->used;
	m->sign = n->sign;
	clone_vector(n->digits, m->digits, n->used);
	return m;
}

void spCopyDigits(BD n, BD m)
{
	size_t i;
	if (m->alloc < n->used)
		spAugmentInSizeDB(m, n->used - m->alloc);
	m->used = n->used;
	for (i = 0; i < n->used; i++)
		m->digits[i] = n->digits[i];
}

size_t spSizeOfBD(BD n)
/* Returns number of significant digits in BD */
{
	size_t k = n->used;
	while (k--)
	{
		if (n->digits[k] != 0)
			return (++k);
	}
	return 0;
}

size_t spBitsInBD(BD n)
/* Returns number of significant bits in BD */
{
	size_t i, bits;
	size_t ndigits;
	digit mask;

	if ((n == NULL) || n->used == 0)
		return 0;
	ndigits = spSizeOfBD(n);
	if (ndigits == 0)
		return 0;
	
	for (i = 0, mask = HIBITMASK; mask > 0; mask >>= 1, i++)
	{
		if (n->digits[ndigits - 1] & mask)
			break;
	}
	bits = ndigits * BITS_PER_DIGIT - i;
	
	return bits;
}

size_t spBytesInBD(BD n)
/* Returns number of significant bits in BD */
{
	size_t t;
	t = spBitsInBD(n);
	return (t + 7) / 8;
}

size_t spLowerBitsZeroInBD(BD n)
/*
  Return the initial bits equals to zero in n, i.e.,
  the exponent of the greatest power of 2 that divides n

  If n == 0, return 0
*/
{
	size_t i, bits;
	digit m, mask;

	if ((n == NULL) || n->used == 0)
		return 0;

	i = 0;
	while ((i < n->used) && (n->digits[i] == 0))
		i++;
	bits = i * BITS_PER_DIGIT;
	m = n->digits[i];
	for (i = 0, mask = 1; mask > 0; mask <<= 1, i++)
		if (m & mask)
			break;
	return bits + i;
}

int8_t spGetBit(BD n, size_t bit)
/* Returns value 1 or 0 of bit n (0..nbits-1); or -1 if out of range */
{
	size_t idigit, to_get;
	digit mask;

	idigit = bit / BITS_PER_DIGIT;
	if (idigit >= n->used)
		return -1;

	/* Set mask */
	to_get = bit % BITS_PER_DIGIT;
	mask = (digit) 1 << to_get;
	return ((n->digits[idigit] & mask) ? 1 : 0);
}

unsigned char spGetByte(BD n, size_t byte)
/*
  Returns the byte at position byte in n->digits as a
  unsigned char
*/
{
	unsigned char *aux;
	aux = (unsigned char *)(n->digits);
	return *(aux + byte);
}

int spCompareAbsoluteValues(BD n1, BD n2)
/*  Returns:
    1 if |n1| > |n2|
		-1 if |n1| < |n2|
    0 if |n1| == |n2|
*/
{
	size_t t1, t2, i;
	t1 = spSizeOfBD(n1);
	t2 = spSizeOfBD(n2);
	if (t1 > t2)
		return 1;
	if (t1 < t2)
		return -1;

	/* t1 == t2 */
	for (i = 0; i < t1; i++)
	{
		digit x1, x2;
		x1 = n1->digits[t1 - i - 1];
		x2 = n2->digits[t1 - i - 1];
		if (x1 > x2)
			return 1;
		if (x1 < x2)
			return -1;
	}
	return 0;
}

digit spAddTo(digit * n, digit n1, digit carry)
{
	digit t = 0;
	*n += carry;
	if (*n < carry)
		t = 1;
	*n += n1;
	if (*n < n1)
		t++;
	return t;
}

digit spSubtractTo(digit * n, digit n1, digit carry)
{
	digit t = 0;
	*n -= carry;
	if (*n > MAX_DIGIT - carry)
		t = 1;
	*n -= n1;
	if (*n > MAX_DIGIT - n1)
		t++;
	return t;
}

void spAddDigitToBD(BD n, digit m, size_t pos)
/*
  Computes n = n + m*B^pos
  If necessary expands n
*/
{
	digit t = 0;
	size_t i = pos;
	if (m == 0)
		return;
	while (pos >= n->alloc)
		spAugmentDB(n);
	if (n->used < pos + 1)
		n->used = pos + 1;

	t = spAddTo(n->digits + i, m, t);
	while (t > 0)
	{
		i++;
		if (i > n->alloc)
			spAugmentDB(n);
		if (i > n->used)
			n->used++;
		t = spAddTo(n->digits + i, 0, t);
	}
}

void spSubtractDigitToBD(BD n, digit m)
/*
  Computes n = n - m
*/
{
	size_t ndigits;
	if (m == 0)
		return;
	ndigits = spSizeOfBD(n);
	if (ndigits == 0)
	{
		n->digits[0] = m;
		n->sign = -1;
		return;
	}
	if (ndigits == 1)
	{
		n->digits[0] -= m;
		if (n->digits[0] > MAX_DIGIT - m)
			n->sign = -1;
		return;
	}
	digit t = 0;
	size_t i = 0;
	t = spSubtractTo(n->digits, m, 0);
	while (t > 0)
	{
		i++;
		t = spSubtractTo(n->digits + i, 0, t);
	}
	n->used = spSizeOfBD(n);
}

BD spPartOfBD(BD n, size_t begin, size_t length)
/*
  Return an auxiliary pointer to a part of a BD
*/
{
	if (begin + length > n->used)
		return NULL;
	BD r;
	if ((r = spAllocBD()) == NULL)
		return NULL;
	r->used = length;
	r->digits = (digit *) (n->digits + begin);
	r->sign = 1;
	r->alloc = 0;
	return r;
}

int spIsZeroBD(BD n)
{
	return (spSizeOfBD(n) == 0) ? 1 : 0;
}

uint8_t spIsOneBD(BD n)
{
	if (spSizeOfBD(n) != 1)
		return 0;
	if (n->digits[0] != 1)
		return 0;
	if (n->sign != 1)
		return 0;
	return 1;
}

BD spInitWithIntegerBD(signeddigit m)
{
	BD n;
	if ((n = spInitWithAllocBD(1)) == NULL)
		return NULL;
	n->used = 1;
	n->sign = (m >= 0) ? 1 : -1;
	n->digits[0] = (m >= 0) ? (digit) m : (digit) (-m);
	return n;
}

void spPrintBinary(digit m, char *text)
{
	printf("%s = ", text);
	size_t i;
	digit mask;
	for (i = BITS_PER_DIGIT; i > 0; i--)
	{
		mask = (digit) 1 << (i - 1);
		printf("%u", (m & mask) ? 1 : 0);
	}
	printf("\n");
}

void spPrintByte(unsigned char b, char *text)
{
	printf("%s = ", text);
	size_t i;
	unsigned char mask;
	for (i = 8; i > 0; i--)
	{
		mask = (unsigned char)1 << (i - 1);
		printf("%u", (b & mask) ? 1 : 0);
	}
	printf("\n");
}

void spFreeString(char **s)
{
	if (*s == NULL)
		return;
	free(*s);
	*s = NULL;
}

void spFreeZeroData(char **s,size_t length)
{
	if (*s == NULL)
		return;
	memset(*s,0,length);
	free(*s);
	*s = NULL;
}

char *getPassword(const char *text)
{
	char *password;
	char c;
	static struct termios oldt, newt;
	size_t alloc_size, str_size;

	printf("%s", text);
	alloc_size = ALLOCSIZE;
	str_size = 0;
	make_vector(password, alloc_size);

	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);

	while (((c = getchar()) != '\n') && (c != EOF))
	{
		if (str_size == alloc_size)
		{
			alloc_size += ALLOCSIZE;
			expand_vector(password, alloc_size);
		}
		password[str_size++] = c;
	}
	if (str_size == alloc_size)
	{
		alloc_size += ALLOCSIZE;
		expand_vector(password, 8);
	}
	password[str_size] = '\0';
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	printf("\n");
	return password;
}

char *getAndVerifyPassphrase(unsigned int msize)
{
	char *p1, *p2;
	p1 = p2 = NULL;

	p1 = getPassword("Enter the encryption passphrase: ");
	p2 = getPassword("Verifying. Enter the encryption passphrase again: ");

	if ((strlen(p1) != strlen(p2)) || (memcmp(p1, p2, strlen(p1)) != 0))
		goto errorVerify;
	if (strlen(p1) < msize)
		goto errorTooShort;

	freeString(p2);
	return p1;

errorVerify:
	freeString(p1);
	freeString(p2);
	fprintf(stderr, "The two passphrases does not coincide. Try again\n");
	return NULL;

errorTooShort:
	freeString(p1);
	freeString(p2);
	fprintf(stderr,"Passphrase too short. It must have at least %u characters\n",msize);
	return NULL;
}

void textToSHA256(char *text, unsigned char *sha)
{
	sha256_ctx ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, (unsigned char *)text, strlen(text));
	sha256_final(&ctx, sha);
}

unsigned char *clearCcommentsInText(unsigned char *string,const unsigned char *begin,const unsigned char *end)
{
	unsigned char *p, *q;

	p = q = NULL;
	if ((p = (unsigned char *)strstr((char *)string,begin)) != NULL) {
		p += strlen((char *)begin);
		while (*p == '\n')
			p++;
		if ((q = (unsigned char *)strstr((char *)p,end)) == NULL)
			return NULL;
		*q = '\0';
		return p;
	}
	return NULL;
}

