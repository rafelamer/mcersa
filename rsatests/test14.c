#include <mce/mcersa.h>
#include <mce/oaep.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv)
{
	BD m, c, n;
	int ret;
	PrivateRSAKey r1;
	m = c = n = NULL;
	ret = EXIT_FAILURE;
	if ((r1 = bdReadPrivateRSAKeyFromFile("mce.key")) == NULL)
		goto final;

	if ((m = spReadBDFromFile("M.txt")) == NULL)
		goto final;

	printf("Actual message = ");
	spPrintDecimal(m);

	if ((c = publicEncryptOAEPRSA(r1->pub, m)) == NULL)
		goto final;

	printf("Encrypted message = ");
	spPrintDecimal(c);

	if ((n = privateDecryptOAEPRSA(r1, c)) == NULL)
		goto final;

	printf("Decrypted message = ");
	spPrintDecimal(n);

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
	if (ret == EXIT_FAILURE)
		printf("Error reading the RSA key, encrypting or decrypting\n");
	return ret;
}
