/**************************************************************************************
* Filename:   addition.c
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

int bdCompareAbsoluteValues(BD n1, BD n2)
/*  Returns:
    1 if n1 > n2
		-1 if n1 < n2
    0 if n1 == n2
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

BD bdAddAbsoluteValues(BD n1, BD n2)
{
	BD l, s, n;
	int cmp;
	
	cmp = bdCompareAbsoluteValues(n1, n2);
	if (cmp >= 0)
	{
		l = n1;
		s = n2;
	} else
	{
		s = n1;
		l = n2;
	}
	if ((n = spCopyBD(l)) == NULL)
		return NULL;
	
	size_t i;
	digit t;
	t = 0;
	for (i = 0; i < s->used; i++)
		t = spAddTo(n->digits + i, s->digits[i], t);
	
	while (t > 0)
	{
		if (n->used == n->alloc)
			if (! spAugmentDB(n))
			{
				freeBD(n);
				return NULL;
			}
		t = spAddTo(n->digits + i, 0, t);
		i++;
		if (i > n->used)
			n->used = i;
	}
	return n;
}

uint8_t bdAddAbsoluteValueTo(BD n1, BD n2)
/*
  The algorithm uses the absolute values of n1 and n2
	
  n1 = n1 + n2 
*/
{
	size_t i;
	digit t;
	if (n1->used == n1->alloc)
		if (!spAugmentInSizeDB(n1, ALLOCSIZE))
			return 0;
	t = 0;
	for (i = 0; i < n2->used; i++)
		t = spAddTo(n1->digits + i, n2->digits[i], t);
	while (t > 0)
	{
		t = spAddTo(n1->digits + i, 0, t);
		i++;
		if (i > n1->used)
			n1->used = i;
	}
	return 1;
}

BD bdSubtractAbsoluteValues(BD n1, BD n2, int8_t * sign)
{
	int cmp;
	BD l, s, n;
	cmp = bdCompareAbsoluteValues(n1, n2);
	if (cmp == 0)
	{
		*sign = 1;
		return spInitBD();
	} else if (cmp == 1)
	{
		l = n1;
		s = n2;
		*sign = 1;
	} else
	{
		s = n1;
		l = n2;
		*sign = -1;
	}
	if ((n = spCopyBD(l)) == NULL)
		return NULL;

	size_t i;
	digit t;
	t = 0;
	for (i = 0; i < s->used; i++)
		t = spSubtractTo(n->digits + i, s->digits[i], t);
	while (t > 0)
		t = spSubtractTo(n->digits + i++, 0, t);
	n->used = spSizeOfBD(n);
	return n;
}

void bdSubtractAbsoluteValuesTo(BD n1, BD n2)
{
	int cmp;
	cmp = bdCompareAbsoluteValues(n1, n2);
	if (cmp <= 0)
	{
		spSetZeroBD(n1);
		return;
	}
	size_t i;
	digit t;
	t = 0;
	for (i = 0; i < n2->used; i++)
		t = spSubtractTo(n1->digits + i, n2->digits[i], t);
	while (t > 0)
		t = spSubtractTo(n1->digits + i++, 0, t);
	n1->used = spSizeOfBD(n1);
}

BD bdAddBD(BD n1, BD n2)
/*
  Returns n1 + n2
*/
{
	int8_t sign;
	BD n;

	sign = n1->sign * n2->sign;
	if (sign == 0)
		return NULL;

	if (sign == 1)
	{
		n = bdAddAbsoluteValues(n1, n2);
		n->sign = n1->sign;
		return n;
	}
	n = bdSubtractAbsoluteValues(n1, n2, &sign);
	n->sign = n1->sign * sign;
	return n;
}

int bdAddUnsignedTo(BD n, BD z, size_t pos)
/*
  Computes n = n + z*B^pos
  Returns: 0 if OK
	-1 if n can't contain the result
*/
{
	digit t;
	size_t i;
	t = 0;
	for (i = 0; i < z->used; i++)
	{
		if (i + pos >= n->alloc)
			return -1;
		t = spAddTo(n->digits + i + pos, z->digits[i], t);
		if (i + pos >= n->used)
			n->used = i + pos + 1;
	}
	i = z->used;
	while (t > 0)
	{
		if (i + pos >= n->alloc)
			return -1;
		t = spAddTo(n->digits + i + pos, 0, t);
		if (i + pos >= n->used)
			n->used = i + pos + 1;
		i++;
	}
	return 0;
}
