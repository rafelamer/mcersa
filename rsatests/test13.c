#include <mce/mcersa.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	PrivateRSAKey r1;
	PublicRSAKey r2;

	BD m, c, n;
	int ret;
	size_t nbytes;

	r1 = NULL;
	r2 = NULL;
	m = c = n = NULL;
	ret = EXIT_FAILURE;

	if ((r1 = bdReadPrivateRSAKeyFromFile("mce.key")) == NULL)
		goto final;
	if ((r2 = bdReadPublicRSAKeyFromFile("mce.pub")) == NULL)
		goto final;

	nbytes = spBytesInBD(r1->pub->n);
	printf("Bytes in the modulus %lu\n", nbytes);

	/*
	   Random message
	 */
	printf("Generating a random message\n\n");
	if ((m = spRandomBD(nbytes - 1)) == NULL)
		goto final;
	printf("m = ");
	spPrintDecimal(m);

	/*
	   Encrypting
	 */

	printf("Encrypting the message m\n\n");
	if ((c = publicEncryptRSA(r2, m)) == NULL)
		goto final;
	printf("c = ");
	spPrintDecimal(c);

	/*
	   Decrypting
	 */
	if ((n = privateDecryptRSA(r1, c)) == NULL)
		goto final;

	if (spCompareAbsoluteValues(m, n) == 0)
		printf("Encryption and decryption OK\n");
	else
		printf
		    ("Encryption or decryption error. You are a bad programmer\n");

	ret = EXIT_SUCCESS;

 final:
	freeBD(m);
	freeBD(c);
	freeBD(n);
	freePrivateRSAKey(r1);
	freePublicRSAKey(r2);
	if (ret == EXIT_FAILURE)
		printf("Error reading the RSA key, encrypting or decrypting\n");
	return ret;
}
