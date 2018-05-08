/**********************************************************************************
* Filename:   test03.c
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
	BD n1, n2, r, q;
	int ret;

	ret = EXIT_FAILURE;
	n1 = n2 = r = q = NULL;
	if ((n1 = spReadBDFromFile("A.txt")) == NULL)
		goto final;
	if ((n2 = spReadBDFromFile("C.txt")) == NULL)
		goto final;

	printf("n1 = ");
	spPrintDecimal(n1);
	printf("n2 = ");
	spPrintDecimal(n2);

	/*
	   Division
	 */
	if ((r = bdDivideSimpleBD(n1, n2, &q)) == NULL)
		goto final;

	printf("n1 = q * n2 + r, where\n");
	printf("q = ");
	spPrintDecimal(q);

	printf("r = ");
	spPrintDecimal(r);

	ret = EXIT_SUCCESS;

 final:
	freeBD(r);
	freeBD(q);
	freeBD(n1);
	freeBD(n2);
	if (ret == EXIT_FAILURE)
		printf("Error with some operations\n");
	return ret;
}
