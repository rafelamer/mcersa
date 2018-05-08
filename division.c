/**************************************************************************************
* Filename:   division.c
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

BD bdDivideSimpleBD(BD n1, BD n2, BD * q)
/*
  Integer division
  Returns r and q such that n1 = q * n2 + r 
 */
{

	BD x, y, t1, t2, t3;
	size_t i, n, t;
	digit norm;
	uint8_t neg;
	int cmp;

	neg = (n1->sign == n2->sign) ? 1 : -1;
	/*
	   Error case: n2 == 0
	 */
	if (spIsZeroBD(n2))
		return NULL;
	/*
	   Trivial case 1: n1 == 0
	 */
	if (spIsZeroBD(n1))
	  {
		  *q = spInitWithAllocBD(1);
		  x = spInitWithAllocBD(1);
		  return x;
	  }
	/*
	   Trivial case 2: n1 == n2
	 */
	if ((cmp = spCompareAbsoluteValues(n1, n2)) == 0)
	  {
		  *q = spInitWithIntegerBD(1);
		  (*q)->sign = neg;
		  x = spInitWithAllocBD(1);
		  return x;
	  }
	/*
	   Trivial case 3: |n1| < |n2| 
	 */
	if (cmp == -1)
	  {
		  if (neg == 1)
		    {
			    *q = spInitWithAllocBD(1);
			    x = spCopyBD(n1);
			    return x;
		  } else
		    {
			    *q = spInitWithIntegerBD(-1);
			    x = spCopyBD(n2);
			    bdSubtractAbsoluteValuesTo(x, n1);
			    return x;
		    }
	  }
	/*
	   General case: |n1| > |n2| 
	   First, we initialize the variables *q, t1, t2, x and y
	 */
	if ((*q = spInitWithAllocBD(n1->used + 2)) == NULL)
		return NULL;
	(*q)->used = n1->used + 2;
	if (((t1 = spInitBD()) == NULL) ||
	    ((t2 = spInitBD()) == NULL) ||
	    ((x = spCopyBD(n1)) == NULL) || ((y = spCopyBD(n2)) == NULL))
		goto ERRORINIT;

	x->sign = y->sign = 1;
	norm = spBitsInBD(y) % BITS_PER_DIGIT;
	if (norm < (BITS_PER_DIGIT - 1))
	  {
		  norm = BITS_PER_DIGIT - 1 - norm;
		  spMultiplyByPowerOfTwo(x, norm);
		  spMultiplyByPowerOfTwo(y, norm);
	} else
	  {
		  norm = 0;
	  }

	n = x->used - 1;
	t = y->used - 1;
	spShiftToLeftNumberOfDigits(y, n - t);

	while (spCompareAbsoluteValues(x, y) != -1)
	  {
		  (*q)->digits[n - t]++;
		  bdSubtractAbsoluteValuesTo(x, y);
	  }
	spShiftToRightNumberOfDigits(y, n - t);
	for (i = n; i > t; i--)
	  {
		  size_t k = i - t - 1;
		  if (i > x->used)
			  continue;
		  if (x->digits[i] == y->digits[t])
		    {
			    (*q)->digits[k] = MAX_DIGIT;
		  } else
		    {
			    doubledigit z;
			    z = (doubledigit) (x->digits[i]) << BITS_PER_DIGIT;
			    z |= (doubledigit) (x->digits[i - 1]);
			    z /= (doubledigit) (y->digits[t]);
			    if (z > (doubledigit) MAX_DIGIT)
				    z = MAX_DIGIT;
			    (*q)->digits[k] = (digit) z;
		    }
		  (*q)->digits[k] = (*q)->digits[k] + 1;
		  do
		    {
			    (*q)->digits[k] = (*q)->digits[k] - 1;
			    spSetZeroBD(t1);
			    t1->digits[0] = (t == 0) ? 0 : y->digits[t - 1];
			    t1->digits[1] = y->digits[t];
			    t1->used = 2;
			    spMultiplyByDigitBD(t1, (*q)->digits[k]);
			    t2->digits[0] = (i < 2) ? 0 : x->digits[i - 2];
			    t2->digits[1] = (i < 1) ? 0 : x->digits[i - 1];
			    t2->digits[2] = x->digits[i];
			    t2->used = 3;
		    }
		  while (spCompareAbsoluteValues(t1, t2) == 1);

		  spCopyDigits(y, t1);
		  spMultiplyByDigitBD(t1, (*q)->digits[k]);
		  spShiftToLeftNumberOfDigits(t1, k);
		  t3 = bdSubtractBD(x, t1);
		  spCopyDigits(t3, x);
		  freeBD(t3);
		  if (x->sign == -1)
		    {
			    spCopyDigits(y, t1);
			    spShiftToLeftNumberOfDigits(t1, k);
			    t3 = bdAddBD(x, t1);
			    spCopyDigits(t3, x);
			    freeBD(t3);
		    }
	  }
	spShiftToRightNumberOfBits(x, norm);
	if (neg == 1)
	  {
		  (*q)->sign = 1;
		  (*q)->used = spSizeOfBD(*q);
		  x->sign = (x->used == 0) ? 1 : n1->sign;
	} else
	  {
		  (*q)->sign = -1;
		  spAddDigitToBD(*q, 1, 0);
		  (*q)->used = spSizeOfBD(*q);
		  t1 = spCopyBD(n2);
		  bdSubtractAbsoluteValuesTo(t1, x);
		  spCopyDigits(t1, x);
		  freeBD(t1);
		  x->sign = (x->used == 0) ? 1 : n2->sign;
	  }
	freeBD(t1);
	t1 = NULL;
	freeBD(t2);
	t2 = NULL;
	freeBD(y);
	y = NULL;
	return x;

 ERRORINIT:
	freeBD(*q);
	*q = NULL;
	freeBD(t1);
	t1 = NULL;
	freeBD(t2);
	t2 = NULL;
	freeBD(x);
	x = NULL;
	freeBD(y);
	y = NULL;
	return NULL;
}
