/**************************************************************************************
* Filename:   spdivide.c
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

int spIsPowerOfTwo(digit m, size_t * power)
/*
  Returns 1 if m is a power of 2
	0 otherwise
  If m = 2^p, then we set *power = p
*/
{
	if ((m == 0) || ((m & (m - 1)) != 0))
		return 0;

	size_t i;
	for (i = 0; i < BITS_PER_DIGIT; i++)
	{
		if (m == (((digit) 1) << i))
		{
			*power = i;
			return 1;
		}
	}
	return 0;
}

BD spModulusByPowerOfTwo(BD n, digit power)
/*
  Returns n % (2^power)
*/
{
	BD m;
	digit b, i;

	if ((power == 0) || (spSizeOfBD(n) == 0))
		return spInitBD();

	if ((m = spCopyBD(n)) == NULL)
		return NULL;

	b = (power + BITS_PER_DIGIT - 1) / BITS_PER_DIGIT;
	for (i = b; i < m->used; i++)
		m->digits[i] = 0;

	i = power % BITS_PER_DIGIT;
	m->digits[b - 1] &= ((digit) 1 << i) - (digit) 1;
	m->used = spSizeOfBD(m);
	return m;
}

void spShiftToRightNumberOfDigits(BD n, digit ndigits)
{
	if (ndigits == 0)
		return;
	if (n->used <= ndigits)
	{
		spSetZeroBD(n);
		return;
	}

	digit *top, *bottom;
	size_t i;
	bottom = n->digits;
	top = n->digits + ndigits;

	for (i = 0; i < n->used - ndigits; i++)
		*bottom++ = *top++;

	for (; i < n->used; i++)
		*bottom++ = 0;
	n->used = spSizeOfBD(n);
}

BD spDivideByPowerOfTwo(BD n, digit power)
/*
  Divides n by 2^power, i.e., shifts to the left a certain number of bits
  Returns the remainder, i.e., the bits discarded
*/
{
	digit d;
	BD r;

	if ((power == 0) || (spSizeOfBD(n) == 0))
		return spInitBD();
	/*
		Remainder
	*/
	if ((r = spModulusByPowerOfTwo(n, power)) == NULL)
		return NULL;

	/*
		Quotient
		If power is 150 and BITS_PER_DIGIT is 32, 150 / 32 = 4
		we first shifts right 4 digits
	*/
	if (power >= BITS_PER_DIGIT)
		spShiftToRightNumberOfDigits(n, power / BITS_PER_DIGIT);
	if (spSizeOfBD(n) == 0)
		return r;
	/*
		d = 150 % 32 = 22
		and we have to shift right 22 bits
	*/
	d = power % BITS_PER_DIGIT;
	if (d == 0)
		return r;

	digit mask, shift, r0, r1;
	digit *aux;
	/*
		mask = 00000000001111111111111111111111
		shift = 10
	*/
	shift = BITS_PER_DIGIT - d;
	mask = ((digit) 1 << d) - 1;
	aux = n->digits + (n->used - 1);
	r0 = 0;
	while (aux >= n->digits)
	{
		r1 = *aux & mask;
		*aux = (*aux >> d) | (r0 << shift);
		aux--;
		r0 = r1;
	}
	n->used = spSizeOfBD(n);
	return r;
}

void spShiftToRightNumberOfBits(BD n, digit nbits)
/*
  Is the same function spDivideByPowerOfTwo, but discarding
  the remainder
*/
{
	if ((nbits == 0) || (spSizeOfBD(n) == 0))
		return;

	if (nbits >= BITS_PER_DIGIT)
		spShiftToRightNumberOfDigits(n, nbits / BITS_PER_DIGIT);
	if (spSizeOfBD(n) == 0)
		return;

	nbits %= BITS_PER_DIGIT;
	if (nbits == 0)
		return;

	digit mask, shift, r0, r1;
	digit *aux;
	shift = BITS_PER_DIGIT - nbits;
	mask = ((digit) 1 << nbits) - 1;
	aux = n->digits + (n->used - 1);
	r0 = 0;
	while (aux >= n->digits)
	{
		r1 = *aux & mask;
		*aux = (*aux >> nbits) | (r0 << shift);
		aux--;
		r0 = r1;
	}
	n->used = spSizeOfBD(n);
}

int spDivideByDigitBD(BD n, digit m, digit * r)
{
	size_t p, i;

	if (m == 0)
		return -1;
	*r = 0;
	if ((m == 1) || (spSizeOfBD(n) == 0))
		return 1;
	/*
		m is a power of two
	*/
	if (spIsPowerOfTwo(m, &p))
	{
		BD res;
		if ((res = spDivideByPowerOfTwo(n, p)) == NULL)
			return -1;
		if (res->used == 0)
			*r = 0;
		else if (res->used == 1)
			*r = res->digits[0];
		else
		{
			freeBD(res);
			return -1;
		}
		freeBD(res);
		return 1;
	}
	/*
		General case
	*/
	doubledigit w = 0;
	digit t;
	for (p = 0; p < n->used; p++)
	{
		i = n->used - p - 1;
		w = (w << BITS_PER_DIGIT) | ((doubledigit) n->digits[i]);
		if (w >= m)
		{
			t = (digit) (w / m);
			w -= ((doubledigit) t) * ((doubledigit) m);
		} else
		{
			t = 0;
		}
		n->digits[i] = (digit) t;
	}
	*r = (digit) w;
	n->used = spSizeOfBD(n);
	return 1;
}
