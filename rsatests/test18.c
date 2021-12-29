/**********************************************************************************
* Filename:   test18.c
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
#include <string.h>

int main(int argc, char **argv)
{
	BD n1, n2, n;
	int ret;

	n1 = n2 = n = NULL;
	ret = EXIT_FAILURE;
	if ((n1 = spRandomBD(BYTES_PER_DIGIT * 7000)) == NULL)
		goto final;

	if ((n2 = spRandomBD(BYTES_PER_DIGIT * 7000)) == NULL)
		goto final;

	if ((n = bdMultiplyBD(n1, n2)) == NULL)
		goto final;

	unsigned char *s;
  s = spBDToString(n1, 10);
	writeFileBinaryMode("n1.txt",s,strlen(s));
	freeString(s);

	s = spBDToString(n2, 10);
	writeFileBinaryMode("n2.txt",s,strlen(s));
	freeString(s);

	s = spBDToString(n, 10);
	writeFileBinaryMode("n.txt",s,strlen(s));
	freeString(s);

	ret = EXIT_SUCCESS;

 final:
	freeBD(n);
	freeBD(n1);
	freeBD(n2);
	if (ret == EXIT_FAILURE)
		printf("Error with some operations\n");
	return ret;
}
