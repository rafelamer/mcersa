/**********************************************************************************
* Filename:   test01.c
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
	BD n1, n2, n3, n;
	int ret;

	ret = EXIT_FAILURE;
	n1 = n2 = n3 = n = NULL;
	if ((n1 = spReadBDFromFile("A.txt")) == NULL)
		goto final;
	if ((n2 = spReadBDFromFile("B.txt")) == NULL)
		goto final;
	if ((n3 = spReadBDFromFile("C.txt")) == NULL)
		goto final;
	printf("n1 = ");
	spPrintDecimal(n1);
	printf("n2 = ");
	spPrintDecimal(n2);
	printf("n3 = ");
	spPrintDecimal(n3);

	/*
	   Addition n = n1 + n2
	 */
	if ((n = bdAddBD(n1, n2)) == NULL)
		goto final;
	printf("n1 + n2 = ");
	spPrintDecimal(n);
	freeBD(n);

	/*
	   Subtraction n = n3 - n1
	 */
	if ((n = bdSubtractBD(n3, n1)) == NULL)
		goto final;
	printf("n3 - n1 = ");
	spPrintDecimal(n);
	freeBD(n);

	/*
	   Multiplication n = n3 * n2
	 */
	if ((n = bdMultiplyBD(n3, n2)) == NULL)
		goto final;
	printf("n3 * n2 = ");
	spPrintDecimal(n);

	/*
	   Bits, bytes and digits. A digit is a long unsigned integer
	 */
	printf("Bits in n1 = %lu\n", spBitsInBD(n1));
	printf("Bytes in n1 = %lu\n", spBytesInBD(n1));
	printf("Digits in n1 = %lu\n", spSizeOfBD(n1));
	printf("Bits per digit  = %u\n\n", BITS_PER_DIGIT);
	printf("Lower bits in n2 equal to zero   = %lu\n\n",
	       spLowerBitsZeroInBD(n2));

	printf("In base 2, n2 = ");
	spPrintBase2(n2);

	ret = EXIT_SUCCESS;

 final:
	freeBD(n);
	freeBD(n1);
	freeBD(n2);
	freeBD(n3);
	if (ret == EXIT_FAILURE)
		printf("Error with some operations\n");
	return ret;
}
