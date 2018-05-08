/**********************************************************************************
* Filename:   test16.c
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
#include <unistd.h>

int main(int argc, char **argv)
{
	PrivateRSAKey r;
	int ret;

	r = NULL;
	ret = EXIT_FAILURE;
	/*
	   Read an encrypted RSA private key from a file
	 */

	if ((r = bdReadEncryptedPrivateRSAKeyFromFile("crmce.key")) == NULL)
		goto final;

	spPrintRSAPrivateKey(r);
	ret = EXIT_SUCCESS;

 final:
	freePrivateRSAKey(r);

	if (ret == EXIT_FAILURE)
		printf("Error reading the key\n");
	return ret;
}
