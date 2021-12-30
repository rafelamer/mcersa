/**********************************************************************************
* Filename:   test20.c
* Author:     Rafel Amer (rafel.amer AT upc.edu)
* Copyright:  Rafel Amer 2018
* Disclaimer: This code is presented "as is" and it has been written to
*             implement the RSA encryption and decryption algorithm for
*             educational purposes and should not be used in contexts that
*             need cryptographically secure implementation
*
* License:    This file is free software; you can redistribute it and/or
*             modify it under the terms of:
*
*             The GNU General Public License as published by the Free Software
*             Foundation; either version 2 of the License, or (at your option)
*             any later version.
*
*	      See https://www.gnu.org/licenses/
***********************************************************************************/
#include <mce/mcersa.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	int ret;
	BD n1, n2;
	digit m, M;
	ret = EXIT_FAILURE;
	n1 = n2 = NULL;
	if ((n1 = spReadBDFromFile("A.txt")) == NULL)
		goto final;
	if ((n2 = spReadBDFromFile("C.txt")) == NULL)
		goto final;

	BD n;
	if ((n = bdMultiplySimpleBD(n1, n2)) == NULL)
		goto final;

	M = max(n1->used,n2->used);
	m = M / 3;
	if (3*m < M)
		m += 1;

	printf("m = %lld\n",m);

	BD x2, x1, x0, y2, y1, y0;
	x0 = x1 = x2 = y0 = y1 = y2 = NULL;
  x0 = spPartOfBD(n1, 0, m);
	x1 = spPartOfBD(n1, m, m);
	x2 = spPartOfBD(n1, 2*m, n1->used - 2*m);
	y0 = spPartOfBD(n2, 0, m);
	y1 = spPartOfBD(n2, m, m);
	y2 = spPartOfBD(n2, 2*m, n2->used - 2*m);

	/*
	printf("x0 = ");
	spPrintDecimal(x0);
	printf("x1 = ");
	spPrintDecimal(x1);
	printf("x2 = ");
	spPrintDecimal(x2);
	printf("y0 = ");
	spPrintDecimal(y0);
	printf("y1 = ");
	spPrintDecimal(y1);
	printf("y2 = ");
	spPrintDecimal(y2);
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

	printf("p1 = ");
	spPrintDecimal(p1);
	printf("pm1 = ");
	spPrintDecimal(pm1);
	printf("pm2 = ");
	spPrintDecimal(pm2);

	BD q1, qm1, qm2;
	q1 = qm1 = qm2 = NULL;
	p = bdAddBD(y0,y2);
	q1 = bdAddBD(p,y1);
	qm1 = bdSubtrackBD(p,y1);
	qm2 = bdAddBD(qm1,y2);
	spMultiplyByDigitBD(qm2,2);
	dbAddMultipleBDTo(&qm2,y0,1,-1);
	freeBD(p);

	printf("q1 = ");
	spPrintDecimal(q1);
	printf("qm1 = ");
	spPrintDecimal(qm1);
	printf("qm2 = ");
	spPrintDecimal(qm2);

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

	printf("r0 = ");
	spPrintDecimal(r0);
	printf("r1 = ");
	spPrintDecimal(r1);
	printf("rm1 = ");
	spPrintDecimal(rm1);
	printf("rm2 = ");
	spPrintDecimal(rm2);
 	printf("rinf = ");
	spPrintDecimal(rinf);

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

	printf("s0 = ");
	spPrintDecimal(r0);
	printf("s1 = ");
	spPrintDecimal(s1);
	printf("s2 = ");
	spPrintDecimal(s2);
	printf("s3 = ");
	spPrintDecimal(s3);
	printf("s4 = ");
	spPrintDecimal(rinf);

	spShiftToLeftNumberOfDigits(s1,m);
	dbAddMultipleBDTo(&s1,r0,1,1);

	spShiftToLeftNumberOfDigits(s2,2*m);
	dbAddMultipleBDTo(&s2,s1,1,1);

	spShiftToLeftNumberOfDigits(s3,3*m);
	dbAddMultipleBDTo(&s3,s2,1,1);

	spShiftToLeftNumberOfDigits(rinf,4*m);
	dbAddMultipleBDTo(&rinf,s3,1,1);
	
	/*
	printf("n1 = ");
	spPrintDecimal(n1);

	printf("n2 = ");
	spPrintDecimal(n2);

	printf("n = ");
	spPrintDecimal(rinf);
	*/

	if (spCompareAbsoluteValues(n, rinf) == 0)
	{
		printf("Final result OK\n");
	}
	else
	{
		/*
		printf("r = ");
		spPrintDecimal(rinf);
		printf("n = ");
		spPrintDecimal(n);
		*/
	}
	ret = EXIT_SUCCESS;

final:
	freeBD(n1);
	freeBD(n2);
	freeBD(n);
	freeBD(r0);
	freeBD(rinf);
	freeBD(s1);
	freeBD(s2);
	freeBD(s3);

	if (ret == EXIT_FAILURE)
		printf("Error with some operations\n");
	return ret;
}
