/**************************************************************************************
* Filename:   gcd.c
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

BD bdGCDOfBD(BD n1, BD n2)
/*
  The algorithm uses the absolute values of n1 and n2
  Returns r = gcd(n1,n2)
*/
{
	BD u, v;
	size_t lu, lv, l;
	/*
		If n1 == 0 or n2 == 0, return the largest
	*/
	if (spIsZeroBD(n1))
	{
		if ((u = spCopyBD(n2)) == NULL)
			return NULL;
		u->sign = 1;
		return u;
	}
	if (spIsZeroBD(n2))
	{
		if ((u = spCopyBD(n1)) == NULL)
			return NULL;
		u->sign = 1;
		return u;
	}
	/*
		Make copies of n1 and n2
	*/
	if ((u = spCopyBD(n1)) == NULL)
		goto ERRORCOPY;
	if ((v = spCopyBD(n2)) == NULL)
		goto ERRORCOPY;
	u->sign = v->sign = 1;

	/*
		Find the common power of two for u and v
		and divide u and v by such power
	*/
	lu = spLowerBitsZeroInBD(u);
	lv = spLowerBitsZeroInBD(v);
	l = min(lu, lv);
	spShiftToRightNumberOfBits(u, l);
	spShiftToRightNumberOfBits(v, l);

	/*
		Make sure that u is greater than v
	*/
	if (spCompareAbsoluteValues(u, v) == -1)
	{
		BD t;
		t = u;
		u = v;
		v = t;
	}

	while (!spIsZeroBD(v))
	{
		BD r, q;
		r = bdDivideSimpleBD(u, v, &q);
		freeBD(q);
		freeBD(u);
		u = v;
		v = r;
	}
	freeBD(v);
	spMultiplyByPowerOfTwo(u, l);
	return u;

ERRORCOPY:
	freeBD(u);
	freeBD(v);
	return NULL;
}

BD bdLCMOfBD(BD n1, BD n2)
/*
  The algorithm uses the absolute values of n1 and n2
  Returns r = lcm(n1,n2)
*/
{
	BD t, r, q;
	t = r = q = NULL;
	if ((t = bdGCDOfBD(n1, n2)) == NULL)
		goto errorLCM;
	if ((r = bdDivideSimpleBD(n1, t, &q)) == NULL)
		goto errorLCM;
	if (!spIsZeroBD(r))
		goto errorLCM;
	freeBD(t);
	freeBD(r);
	if ((t = bdMultiplyBD(q, n2)) == NULL)
		goto errorLCM;
	freeBD(q);
	return t;

errorLCM:
	freeBD(t);
	freeBD(r);
	freeBD(q);
	return NULL;
}

BD bdExtendedGCDOfBD(BD n1, BD n2, BD * x, BD * y)
/*
  The algorithm uses the absolute values of n1 and n2

  Returns r = gcd(n1,n2);
  and finds x and y such that n1 * x + n2 * y = r
*/
{
	BD u, v, lx, ly;
	size_t lu, lv, l;
	int exch;

	if (spIsZeroBD(n1) || spIsZeroBD(n2))
		return NULL;

	if ((u = spCopyBD(n1)) == NULL)
		goto ERRORCOPYINIT;
	if ((v = spCopyBD(n2)) == NULL)
		goto ERRORCOPYINIT;
	u->sign = v->sign = 1;

	lu = spLowerBitsZeroInBD(u);
	lv = spLowerBitsZeroInBD(v);
	l = min(lu, lv);
	spShiftToRightNumberOfBits(u, l);
	spShiftToRightNumberOfBits(v, l);

	exch = 0;
	if (spCompareAbsoluteValues(u, v) == -1)
	{
		BD t;
		t = u;
		u = v;
		v = t;
		exch = 1;
	}
	if ((*x = spInitWithOneBD()) == NULL)
		goto ERRORCOPYINIT;
	if ((*y = spInitBD()) == NULL)
		goto ERRORCOPYINIT;
	if ((ly = spInitWithOneBD()) == NULL)
		goto ERRORCOPYINIT;
	if ((lx = spInitBD()) == NULL)
		goto ERRORCOPYINIT;

	while (!spIsZeroBD(v))
	{
		BD r, q, t1, t2;
		r = bdDivideSimpleBD(u, v, &q);
		freeBD(u);
		u = v;
		v = r;
		/*
			Extended part for *x and lx
			(lx, x) = ((x - (q * lx)),lx)
		*/
		t1 = bdMultiplyBD(q, lx);
		t2 = bdSubtractBD(*x, t1);
		freeBD(t1);
		*x = lx;
		lx = t2;
		/*
			Extended part for *y and ly
		*/
		t1 = bdMultiplyBD(q, ly);
		t2 = bdSubtractBD(*y, t1);
		freeBD(t1);
		*y = ly;
		ly = t2;

		freeBD(q);
	}
	freeBD(lx);
	freeBD(ly);
	freeBD(v);
	spMultiplyByPowerOfTwo(u, l);
	if (exch == 1)
	{
		BD t;
		t = *y;
		*y = *x;
		*x = t;
	}
	return u;

ERRORCOPYINIT:
	freeBD(u);
	u = NULL;
	freeBD(v);
	v = NULL;
	freeBD(*x);
	*x = NULL;
	freeBD(*y);
	*y = NULL;
	freeBD(lx);
	lx = NULL;
	freeBD(lx);
	ly = NULL;
	return NULL;
}
