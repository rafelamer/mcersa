/**************************************************************************************
* Filename:   multiplication.c
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

BD bdMultiplySimpleBD(BD n1, BD n2)
/*
  Returns n1 * n2
 */
{
	size_t t1, t2, i, j;
	digit t;
	doubledigit p;
	BD n;

	t1 = spSizeOfBD(n1);
	t2 = spSizeOfBD(n2);
	if (t1 * t2 == 0)
		return spInitBD();
	if ((n = spInitWithAllocBD(t1 + t2)) == NULL)
		return NULL;
	n->used = t1 + t2;
	n->sign = n1->sign * n2->sign;
	for (i = 0; i < t1; i++)
	  {
		  if (n1->digits[i] == 0)
			  continue;
		  t = 0;
		  for (j = 0; j < t2; j++)
		    {
			    p = DD(n1->digits[i]) * DD(n2->digits[j]) +
				DD(n->digits[i + j]) + DD(t);
			    n->digits[i + j] = LOHALF(p);
			    t = HIHALF(p);
		    }
		  n->digits[i + t2] = t;
	  }
	n->used = spSizeOfBD(n);
	return n;
}

/*
  Karatsuba
 */

BD karatsuba_simple(BD z0, BD z1, size_t m, size_t ndigits)
{
	BD n;
	if ((n = spInitWithAllocBD(ndigits)) == NULL)
		return NULL;
	n->used = ndigits;
	n->sign = 1;
	if (bdAddUnsignedTo(n, z0, 0) < 0)
	  {
		  freeBD(n);
		  return NULL;
	  }
	if (bdAddUnsignedTo(n, z1, m) < 0)
	  {
		  freeBD(n);
		  return NULL;
	  }
	return n;
}

BD karatsuba_general(BD z2, BD z, BD z0, size_t m, size_t ndigits)
{
	BD n;
	if ((n = spInitWithAllocBD(ndigits)) == NULL)
		return NULL;
	n->used = ndigits;

	if (bdAddUnsignedTo(n, z2, 2 * m) < 0)
	  {
		  freeBD(n);
		  return NULL;
	  }
	if (bdAddUnsignedTo(n, z, m) < 0)
	  {
		  freeBD(n);
		  return NULL;
	  }
	if (bdAddUnsignedTo(n, z0, 0) < 0)
	  {
		  freeBD(n);
		  return NULL;
	  }
	if (bdSubtractUnsignedTo(n, z2, m) < 0)
	  {
		  freeBD(n);
		  return NULL;
	  }
	if (bdSubtractUnsignedTo(n, z0, m) < 0)
	  {
		  freeBD(n);
		  return NULL;
	  }
	return n;
}

BD bdMultiplyKaratsubaBD(BD n1, BD n2)
{
	BD l, s;
	size_t m;
	if (n1->used >= n2->used)
	  {
		  l = n1;
		  s = n2;
	} else
	  {
		  l = n2;
		  s = n1;
	  }
	/*
	   Cas no recursiu
	 */
	if (l->used < 128)
		return bdMultiplySimpleBD(l, s);

	/*
	   Primer cas recursiu. l->used
	 */
	m = (l->used % 2) == 0 ? l->used / 2 : l->used / 2 + 1;
	BD x1, x0;
	x0 = spPartOfBD(l, 0, m);
	x1 = spPartOfBD(l, m, l->used - m);
	if (s->used <= m)
	  {
		  BD z0, z1, r;
		  z0 = bdMultiplyKaratsubaBD(x0, s);
		  z1 = bdMultiplyKaratsubaBD(x1, s);
		  r = karatsuba_simple(z0, z1, m, l->used + s->used);
		  freeBD(z0);
		  freeBD(z1);
		  free(x0);
		  free(x1);
		  r->sign = l->sign * s->sign;
		  return r;
	  }
	/*
	   Segon cas recursiu
	 */
	BD y1, y0, s1, s2, z0, z, z2, r;
	y0 = spPartOfBD(s, 0, m);
	y1 = spPartOfBD(s, m, s->used - m);
	z0 = bdMultiplyKaratsubaBD(x0, y0);
	z2 = bdMultiplyKaratsubaBD(x1, y1);
	s1 = bdAddBD(x1, x0);
	s2 = bdAddBD(y1, y0);
	z = bdMultiplyKaratsubaBD(s1, s2);
	r = karatsuba_general(z2, z, z0, m, l->used + s->used);
	freeBD(z0);
	freeBD(z2);
	freeBD(z);
	freeBD(s1);
	freeBD(s2);
	free(x0);
	free(x1);
	free(y0);
	free(y1);
	r->sign = l->sign * s->sign;
	return r;
}

BD bdMultiplyBD(BD n1, BD n2)
{
	return bdMultiplyKaratsubaBD(n1, n2);
}

uint8_t bdMultiplyBDBy(BD * n1, BD n2)
/*
  n1 = n1 * n2
 */
{
	BD r;
	if ((r = bdMultiplyBD(*n1, n2)) == NULL)
		return 0;
	freeBD(*n1);
	*n1 = r;
	return 1;
}

uint8_t bdExponentialBDToPowerOfTwo(BD * n, size_t power)
/*
  n = n ^ (2 ^ power)
 */
{
	/*
	   Nothing to do
	 */
	if (power == 0)
		return 1;
	if (spIsZeroBD(*n) || spIsOneBD(*n))
		return 1;
	/*
	   Start squaring
	 */
	size_t i;
	BD r;
	for (i = 0; i < power; i++)
	  {
		  if ((r = bdMultiplyBD(*n, *n)) == NULL)
			  return 0;
		  freeBD(*n);
		  *n = r;
	  }
	return 1;
}
