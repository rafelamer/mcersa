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
	/*
		See https://en.wikipedia.org/wiki/Toom-Cook_multiplication

		Split the numbers
	*/
	BD x2, x1, x0, y2, y1, y0;
  x0 = spPartOfBD(l, 0, m);
	x1 = spPartOfBD(l, m, m);
	x2 = spPartOfBD(l, 2*m, l->used - 2*m);
	y0 = spPartOfBD(s, 0, m);
	y1 = spPartOfBD(s, m, m);
	y2 = spPartOfBD(s, 2*m, s->used - 2*m);

	/*
		Evaluation of numbers p1, pm1 and pm2
		Remember thats p0 = x0 and pinf = x2
	*/
	BD p, p1, pm1, pm2;
	p = p1 = pm1 = pm2 = NULL;
	p = bdAddBD(x0,x2);
	p1 = bdAddBD(p,x1);
	pm1 = bdSubtrackBD(p,x1);
	pm2 = bdAddBD(pm1,x2);
	spMultiplyByDigitBD(pm2,2);
	dbAddMultipleBDTo(&pm2,x0,1,-1);
	freeBD(p);

	/*
		Evaluation of numbers q1, qm1 and qm2
		Remember thats q0 = y0 and qinf = y2
	*/
	BD q1, qm1, qm2;
	q1 = qm1 = qm2 = NULL;
	p = bdAddBD(y0,y2);
	q1 = bdAddBD(p,y1);
	qm1 = bdSubtrackBD(p,y1);
	qm2 = bdAddBD(qm1,y2);
	spMultiplyByDigitBD(qm2,2);
	dbAddMultipleBDTo(&qm2,y0,1,-1);
	freeBD(p);

	/*
		Pointwise multiplication
	*/
	BD r0, r1, rm1, rm2, rinf;
	r0 = r1 = rm1 = rm2 = rinf = NULL;
	r0 = bdMultiplyBD(x0,y0);
	r1 = bdMultiplyBD(p1,q1);
	rm1 = bdMultiplyBD(pm1,qm1);
	rm2 = bdMultiplyBD(pm2,qm2);
	rinf = 	bdMultiplyBD(x2,y2);
	freeBD(p1);
	freeBD(pm1);
	freeBD(pm2);
	freeBD(q1);
	freeBD(qm1);
	freeBD(qm2);
	/*
		Interpolation
		Remember that s0 = r0 and s4 = rinf
	*/
	BD s1, s2, s3;
	digit remainder;
	s1 = s2 = s3 = NULL;
	s3 = bdSubtrackBD(rm2,r1);
	spDivideByDigitBD(s3,3,&remainder);
	s1 = bdSubtrackBD(r1,rm1);
	spDivideByDigitBD(s1,2,&remainder);
	s2 = bdSubtrackBD(rm1,r0);
	s3->sign *= -1;
	dbAddMultipleBDTo(&s3,s2,1,1);
	spDivideByDigitBD(s3,2,&remainder);
	dbAddMultipleBDTo(&s3,rinf,2,1);
	dbAddMultipleBDTo(&s2,s1,1,1);
	dbAddMultipleBDTo(&s2,rinf,1,-1);
	dbAddMultipleBDTo(&s1,s3,1,-1);
	freeBD(r1);
	freeBD(rm1);
	freeBD(rm2);

	/*
		Recomposition
	*/
	spShiftToLeftNumberOfDigits(s1,m);
	dbAddMultipleBDTo(&s1,r0,1,1);
	freeBD(r0);
	spShiftToLeftNumberOfDigits(s2,2*m);
	dbAddMultipleBDTo(&s2,s1,1,1);
	freeBD(s1);
	spShiftToLeftNumberOfDigits(s3,3*m);
	dbAddMultipleBDTo(&s3,s2,1,1);
	freeBD(s2);
	spShiftToLeftNumberOfDigits(rinf,4*m);
	dbAddMultipleBDTo(&rinf,s3,1,1);
	freeBD(s3);

	rinf->sign = l->sign * s->sign;
	return rinf;
}
