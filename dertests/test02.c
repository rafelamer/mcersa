/**********************************************************************************
* Filename:   test02.c
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
	BD n1, n2, n3, n4;
	int ret, error;
	Stack st;
	size_t length;
	unsigned long long integer;

	ret = EXIT_FAILURE;
	n1 = n2 = n3 = n4 = NULL;

	if ((n1 = spReadBDFromFile("A.txt")) == NULL)
		goto final;

	if ((n2 = spReadBDFromFile("C.txt")) == NULL)
		goto final;

	if ((st = stInitStack()) == NULL)
		goto final;

	if ((st->data =
	     readFileBinaryMode("test.der", &(st->used), &(st->alloc))) == NULL)
		goto final;
	st->read = st->data;

	length = stReadStartSequenceAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto final;

	printf("Sequence of length %lu\n\n", length);

	integer = stReadInteger(st, &error);
	if (error != 0)
		goto final;

	printf("Integer %llu\n\n", integer);

	if (stReadOptionalRsaEncryptionOI(st) == 1)
		printf("rsaEncryption Object identifier found\n\n");
	else
		printf("rsaEncryption Object identifier not found\n\n");

	integer = stReadInteger(st, &error);
	if (error != 0)
		goto final;

	printf("Integer %llu\n\n", integer);

	n3 = stReadBD(st, &error);
	if ((n3 == NULL) || (error != 0))
		goto final;

	if (spCompareAbsoluteValues(n1, n3) == 0)
	  {
		  printf("The following number has been readed: ");
		  spPrintDecimal(n3);
	  }

	integer = stReadInteger(st, &error);
	if (error != 0)
		goto final;

	printf("Integer %llu\n\n", integer);

	n4 = stReadBD(st, &error);
	if ((n4 == NULL) || (error != 0))
		goto final;

	if (spCompareAbsoluteValues(n2, n4) == 0)
	  {
		  printf("The following number has been readed: ");
		  spPrintDecimal(n4);
	  }

	printf("test.der read successfully\n");

	ret = EXIT_SUCCESS;

 final:
	freeBD(n1);
	freeBD(n2);
	freeBD(n3);
	freeBD(n4);
	freeStack(st);
	if (ret == EXIT_FAILURE)
		printf("Error in DER\n");
	return ret;
}
