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
	BD n1, n2;
	int ret;
	Stack st;

	ret = EXIT_FAILURE;
	n1 = n2 = NULL;
	if ((n1 = spReadBDFromFile("A.txt")) == NULL)
		goto final;
	if ((n2 = spReadBDFromFile("C.txt")) == NULL)
		goto final;

	if ((st = stInitStackWithSize(2048)) == NULL)
		goto final;

	if (!stWriteBD(st, n2))
		goto final;

	if (!stWriteInteger(st, 0))
		goto final;

	if (!stWriteBD(st, n1))
		goto final;

	if (!stWriteInteger(st, 0))
		goto final;

	if (!stWriteRsaEncryptionOI(st))
		goto final;

	if (!stWriteInteger(st, 0))
		goto final;

	if (!stWriteStartSequence(st))
		goto final;

	if (!writeFileBinaryMode("test.der", st->data, st->used))
		goto final;

	printf("test.der written successfully\n");

	ret = EXIT_SUCCESS;

 final:
	freeBD(n1);
	freeBD(n2);
	freeStack(st);
	if (ret == EXIT_FAILURE)
		printf("Error in DER\n");
	return ret;
}

/*
  After compiling and running the program

  ~$ ./test01

  and, then, execute

  ~$ dumpasn1 test.der

  you will have the output

  0 182: SEQUENCE {
  3   1:   INTEGER 0
  6  13:   SEQUENCE {
  8   9:     OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
 19   0:     NULL
       :     }
 21   1:   INTEGER 0
 24  83:   INTEGER
       :     1E E5 B5 BD 00 9D 07 BC A3 16 79 3E 9B 68 50 D7
       :     F0 AB F1 C3 72 B3 81 DD 00 9E 75 A4 8E E5 FF A6
       :     E8 8D 8A 5F 4E 46 69 80 2A 07 20 EC BA 15 A4 2A
       :     47 A0 5B 8D E1 D3 E1 EA 18 E5 59 9A 80 9E 19 08
       :     A7 16 78 50 12 6A 17 04 76 8D 29 95 75 EA 83 35
       :     93 20 5A
109   1:   INTEGER 0
112  71:   INTEGER
       :     13 AF 62 D6 15 AC 45 DC D2 BF 52 8B 3A 1A 35 6C
       :     98 B9 D8 60 BA 28 C5 75 D2 13 BC 5E 5F A0 66 40
       :     FA 76 6C 74 F2 EC 50 15 5B B1 13 93 96 EC 57 84
       :     54 64 5D 38 15 41 CC A3 ED 27 95 33 AE 87 59 0C
       :     B6 9D EB A8 00 00 00
       :   }

0 warnings, 0 errors.

 */
