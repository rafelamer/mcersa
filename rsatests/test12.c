/**********************************************************************************
* Filename:   test12.c
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
	PrivateRSAKey r1, r2;
	int ret;

	r1 = r2 = NULL;
	ret = EXIT_FAILURE;
	/*
	   Generate a pair of private and public RSA keys
	 */

	printf("Generating a 4096 bit private key....\n");

	if ((r1 = genRSAPrivateKey(4096)) == NULL)
		goto final;

	if (!bdWritePublicRSAKeyToFile("mce.pub", r1->pub))
		goto final;

	if (!bdWritePrivateRSAKeyToFile("mce.key", r1))
	  {
		  unlink("mce.pub");
		  goto final;
	  }

	if ((r2 = bdReadPrivateRSAKeyFromFile("mce.key")) == NULL)
		goto final;

	if (spCompareAbsoluteValues(r1->pub->n, r2->pub->n) != 0)
		printf("Error in modulus n\n");
	if (spCompareAbsoluteValues(r1->pub->ek, r2->pub->ek) != 0)
		printf("Error in encryption key ek\n");
	if (spCompareAbsoluteValues(r1->dk, r2->dk) != 0)
		printf("Error in decryption key dk\n");
	if (spCompareAbsoluteValues(r1->p, r2->p) != 0)
		printf("Error in prime p\n");
	if (spCompareAbsoluteValues(r1->q, r2->q) != 0)
		printf("Error in prime q\n");
	if (spCompareAbsoluteValues(r1->kp, r2->kp) != 0)
		printf("Error in coefficient kp\n");
	if (spCompareAbsoluteValues(r1->kq, r2->kq) != 0)
		printf("Error in coefficient kq\n");
	if (spCompareAbsoluteValues(r1->c2, r2->c2) != 0)
		printf("Error in coefficient c2\n");

	ret = EXIT_SUCCESS;

 final:
	freePrivateRSAKey(r1);
	freePrivateRSAKey(r2);

	if (ret == EXIT_FAILURE)
		printf("Error generating the keys\n");
	return ret;
}
