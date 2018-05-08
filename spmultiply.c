/**************************************************************************************
* Filename:   spmultiply.c
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

void spMultiplyByDigitBD(BD n, digit m)
/*
  Computes n = n * m
  If necessary expands n
 */
{
	digit t = 0;
	doubledigit p;
	size_t i = 0;
	size_t d = n->used;
	if (m == 0)
	  {
		  spSetZeroBD(n);
		  return;
	  }
	while (i < d)
	  {
		  p = DD(m) * DD(n->digits[i]) + DD(t);
		  n->digits[i] = LOHALF(p);
		  t = HIHALF(p);
		  i++;
	  }
	if (t == 0)
		return;
	if (n->used == n->alloc)
		spAugmentDB(n);
	n->digits[d] = t;
	n->used++;
}

void spShiftToLeftNumberOfDigits(BD n, digit ndigits)
{
	if ((n->alloc - n->used) < ndigits)
		spAugmentInSizeDB(n, ndigits - (n->alloc - n->used));
	memmove(n->digits + ndigits, n->digits, n->used * sizeof(digit));
	memset(n->digits, 0, ndigits * sizeof(digit));
	n->used += ndigits;
}

void spMultiplyByPowerOfTwo(BD n, digit power)
/*
  Shift to the left a certain number of bits.
 */
{
	size_t newSize, m, i;

	if ((power == 0) || (spSizeOfBD(n) == 0))
		return;

	/*
	   Compute the new size and alloc space for it
	 */
	newSize = (spBitsInBD(n) + power + BITS_PER_DIGIT - 1) / BITS_PER_DIGIT;
	if (newSize > n->alloc)
		spAugmentInSizeDB(n, newSize - n->alloc);
	/*
	   If power is 158 and BITS_PER_DIGIT is 32, 178 / 32 = 5
	   we first shifts letf 5 digits
	 */
	if (power >= BITS_PER_DIGIT)
	  {
		  m = power / BITS_PER_DIGIT;
		  spShiftToLeftNumberOfDigits(n, m);
	  }
	/*
	   The remainder 18  bits
	 */
	m = power % BITS_PER_DIGIT;
	if (m == 0)
		return;

	digit mask, shift, r0, r1;
	digit *aux;
	/*
	   m = 18
	   14              18
	   mask = 00000000000000111111111111111111
	   shift = 32 - 18 = 14 
	 */
	shift = BITS_PER_DIGIT - m;
	mask = ((digit) 1 << m) - 1;
	aux = n->digits;
	r0 = 0;
	for (i = 0; i < n->used; i++)
	  {
		  /*
		     r1 stores the first 18 bits of *aux
		     *aux stores 
		   */
		  r1 = (*aux >> shift) & mask;
		  *aux = ((*aux << m) | r0);
		  aux++;
		  r0 = r1;
	  }
	if (r0 > 0)
		n->digits[n->used++] = r0;
	n->used = spSizeOfBD(n);
}
