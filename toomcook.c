/**************************************************************************************
* Filename:   toomcook.c
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

BD bdMultiplyToomCook(BD l, BD s,size_t m)
{
	BD x2, x1, x0, y2, y1, y0;
  x0 = spPartOfBD(l, 0, m);
	x1 = spPartOfBD(l, m, m);
	x2 = spPartOfBD(l, 2*m, l->used - 2*m);
	y0 = spPartOfBD(s, 0, m);
	y1 = spPartOfBD(s, m, m);
	y2 = spPartOfBD(s, 2*m, l->used - 2*m);

	BD p, p0, p1, pm1, pm2, pinf;
	p0 = x0;
	p = bdAddBD(x0,x2);
	p1 = bdAddBD(p,x1)
	x1->sign = -1
	pm1 = bdAddBD(p,x1)
	x1->sign = 1












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
