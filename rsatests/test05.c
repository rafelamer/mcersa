/**********************************************************************************
* Filename:   test05.c
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
	BD n1, n2, gcd, t1, t2;
	int ret;

	ret = EXIT_FAILURE;
	n1 = n2 = gcd = t1 = t2 = NULL;
	if ((n1 = spReadBDFromFile("D.txt")) == NULL)
		goto final;
	if ((n2 = spReadBDFromFile("E.txt")) == NULL)
		goto final;

	printf("n1 = ");
	spPrintDecimal(n1);
	printf("n2 = ");
	spPrintDecimal(n2);

	/*
	   Extended Euclidean algorithm
	 */
	if ((gcd = bdExtendedGCDOfBD(n1, n2, &t1, &t2)) == NULL)
		goto final;

	printf("gcd(n1,n2) = d = ");
	spPrintDecimal(gcd);

	printf("and t1 * n1 + t2 * n2 = d, where\n");
	printf("t1 = ");
	spPrintDecimal(t1);
	printf("t2 = ");
	spPrintDecimal(t2);

	ret = EXIT_SUCCESS;

 final:
	freeBD(gcd);
	freeBD(n1);
	freeBD(n2);
	freeBD(t1);
	freeBD(t2);
	if (ret == EXIT_FAILURE)
		printf("Error with some operations\n");
	return ret;
}
