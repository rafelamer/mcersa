#include <mce/oaep.h>
#include <mce/tiger.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	int32_t i, padRet;
	uint8_t *EM, *tmp;
	uint8_t hash[3 * hLen];

	if (argc != 2)
	  {
		  printf("Usage\n");
		  return -1;
	  }
	memset(hash, 0xCD, sizeof(hash));
	tiger((uint8_t *) argv[1], strlen(argv[1]), hash + hLen);
	for (i = 0; i < 3 * (int32_t) hLen; i++)
		printf("%02X ", hash[i]);
	printf("\n\n");

	i = 1024;		/* minimum 592 */
	EM = malloc(1024 / 8);
	if (!EM)
	  {
		  printf("Unable to allocate memory for encoded message.\n");
		  return -1;
	  }

	padRet = oaep_encode(hash, sizeof(hash), (1024 / 8), LABEL_CLIENT, EM);
	if (padRet < 0)
	  {
		  printf("Failed to encode message, got %d\n", padRet);
		  return -1;
	  }

	printf("Encoded message:\n");
	for (i = 0; i < (1024 / 8); i++)
		printf("%02X ", EM[i]);
	printf("\n");

	padRet = oaep_decode(EM, (1024 / 8), LABEL_CLIENT);
	if (padRet < 0)
	  {
		  printf("Failed to decode message, got %d\n", padRet);
		  return -1;
	  }
	printf("padRet is %d, hash is %lu bytes\n", padRet, sizeof(hash));

	printf("Decoded message:\n");
	tmp = EM;
	printf("Y:\t\t%02X\n", *tmp);
	tmp++;
	printf("Seed:\t\t");
	for (i = 0; i < (int32_t) hLen; i++, tmp++)
		printf("%02X", *tmp);
	printf("\nDB/lHash':\t");
	for (i = 0; i < (int32_t) hLen; i++, tmp++)
		printf("%02X", *tmp);
	printf("\nDB/PS+0x01:\t");
	for (i = 0; !tmp[i]; i++)
		printf("%02X", tmp[i]);
	printf("%02X\n", tmp[i]);
	tmp += i + 1;
	printf("M:\t\t");
	for (i = 0; i < padRet; i++, tmp++)
		printf("%02X ", *tmp);
	printf("\n");

	free(EM);
	return 0;
}
