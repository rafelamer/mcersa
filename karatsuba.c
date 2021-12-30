/**************************************************************************************
* Filename:   karatsuba.c
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

BD post_karatsuba_simple(BD z0, BD z1, size_t m, size_t ndigits)
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

BD post_karatsuba(BD z2, BD z, BD z0, size_t m, size_t ndigits)
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

BD bdMultiplyKaratsubaSimple(BD l, BD s,size_t m)
{
  BD x1, x0;
  BD z0, z1, r;
  x0 = spPartOfBD(l, 0, m);
	x1 = spPartOfBD(l, m, l->used - m);

	z0 = bdMultiplyBD(x0, s);
	z1 = bdMultiplyBD(x1, s);
	r = post_karatsuba_simple(z0, z1, m, l->used + s->used);
	freeBD(z0);
	freeBD(z1);
	free(x0);
	free(x1);
	r->sign = l->sign * s->sign;
	return r;
}

BD bdMultiplyKaratsuba(BD l, BD s,size_t m)
{
  BD x1, x0, y1, y0;
  x0 = spPartOfBD(l, 0, m);
	x1 = spPartOfBD(l, m, l->used - m);
  y0 = spPartOfBD(s, 0, m);
	y1 = spPartOfBD(s, m, s->used - m);

  BD s1, s2, z0, z, z2, r;
  z0 = bdMultiplyBD(x0, y0);
	z2 = bdMultiplyBD(x1, y1);
	s1 = bdAddBD(x1, x0);
	s2 = bdAddBD(y1, y0);
	z = bdMultiplyBD(s1, s2);
	r = post_karatsuba(z2, z, z0, m, l->used + s->used);
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
