/**************************************************************************************
* Filename:   mcersa.h
* Author:     Rafel Amer (rafel.amer AT upc.edu)
* Copyright:  Rafel Amer 2018
* Disclaimer: This code is presented "as is" and it has been written to 
*             implement the RSA encryption and decryption algorithm for 
*             educational purposes and should not be used in contexts that 
*             need cryptographically secure implementation
*	    
* License:    This library  is free software; you can redistribute it and/or
*             modify it under the terms of either:
*
*             1 the GNU Lesser General Public License as published by the Free
*               Software Foundation; either version 3 of the License, or (at your
*               option) any later version.
*
*             or
*
*             2 the GNU General Public License as published by the Free Software
*               Foundation; either version 2 of the License, or (at your option)
*               any later version.
*
*	      See https://www.gnu.org/licenses/
***************************************************************************************/
#ifndef H_MCERSA_H_
#define H_MCERSA_H_ 1

#include <sys/types.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <limits.h>

#if __WORDSIZE == 64
#define BITS_PER_DIGIT 64
#define BYTES_PER_DIGIT 8
#define HIBITMASK 0x8000000000000000UL
#define MAX_DIGIT 0xFFFFFFFFFFFFFFFFUL
#define MAX_HALF_DIGIT 0xFFFFFFFFUL
typedef unsigned long long int digit;
typedef long long signeddigit;
typedef unsigned __int128 doubledigit;
#else
#define BITS_PER_DIGIT 32
#define BYTES_PER_DIGIT 4
#define HIBITMASK 0x80000000UL
#define MAX_DIGIT 0xFFFFFFFFUL
#define MAX_HALF_DIGIT 0xFFFFUL
typedef unsigned long int digit;
typedef long int signeddigit;
typedef uint64_t doubledigit;
#endif				/* __WORDSIZE */

#define BITS_PER_HALF_DIGIT (BITS_PER_DIGIT / 2)
#define KEK_KEY_LEN 48
#define ITERATION 16
#define ALLOCSIZE  128

#define max(a,b)            (((a) > (b)) ? (a) : (b))
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#define LOHALF(x)           ((digit)(x))
#define HIHALF(x)           ((digit)((x) >> BITS_PER_DIGIT))
#define DD(n)               ((doubledigit)(n))
#define freeBD(n)  spFreeBD(&(n))
#define freeString(s)  spFreeString((char **)(&(s)));
#define freeZeroData(s,n) spFreeZeroData((char **)(&(s)),(n));
#define freePrivateRSAKey(r) spFreeRSAPrivateKey(&(r))
#define freePublicRSAKey(r) spFreeRSAPublicKey(&(r))
#define freeStack(s)   stFreeStack(&(s))

typedef struct {
	size_t used;
	size_t alloc;
	digit *digits;
	int8_t sign;
} big_digit;
typedef big_digit *BD;

typedef struct {
	BD n;			// Modulo
	BD ek;			// Encryption key 
} public_rsa_key;
typedef public_rsa_key *PublicRSAKey;

typedef struct {
	PublicRSAKey pub;
	BD p;			// Prime p
	BD q;			// Prime q 
	BD dk;			// Decryption key 
	BD kp;			// dk mod (p - 1)
	BD kq;			// dk mod (q - 1)
	BD c2;			// q^(-1) mod (p)
} private_rsa_key;
typedef private_rsa_key *PrivateRSAKey;

typedef struct {
	size_t used;
	size_t alloc;
	unsigned char *data;
	unsigned char *read;
} data_stack;
typedef data_stack *Stack;

/*
  Basic functions
 */
BD spAllocBD();
BD spInitBD();
BD spInitWithOneBD();
BD spInitWithAllocBD(size_t alloc);
void spAugmentDB(BD n);
void spAugmentInSizeDB(BD n, size_t ndigits);
void spFreeBD(BD * n);
void spFreeString(char **s);
void spFreeZeroData(char **s,size_t length);
char *getPassword(const char *text);
char *getAndVerifyPassphrase();
BD spCopyBD(BD n);
void spCopyDigits(BD n, BD m);
void spSetZeroBD(BD n);
size_t spSizeOfBD(BD n);
size_t spBitsInBD(BD n);
size_t spBytesInBD(BD n);
size_t spLowerBitsZeroInBD(BD n);
int8_t spGetBit(BD n, size_t bit);
unsigned char spGetByte(BD n, size_t byte);
int spCompareAbsoluteValues(BD n1, BD n2);
BD spPartOfBD(BD n, size_t begin, size_t length);
int spIsZeroBD(BD n);
uint8_t spIsOneBD(BD n);

/*
  Operations with  single digits
 */
digit spAddTo(digit * n, digit n1, digit carry);
digit spSubtractTo(digit * n, digit n1, digit carry);
int spIsPowerOfTwo(digit m, size_t * power);
BD spInitWithIntegerBD(signeddigit m);
void spPrintBinary(digit m, char *text);
void spPrintByte(unsigned char b, char *text);

/*
  Operations with big digits and single digits
  Operates on the absolute value of BD's
 */
void spAddDigitToBD(BD n, digit m, size_t pos);
void spSubtractDigitToBD(BD n, digit m);
void spMultiplyByDigitBD(BD n, digit m);
BD spModulusByPowerOfTwo(BD n, digit power);
void spShiftToRightNumberOfDigits(BD n, digit ndigits);
void spShiftToRightNumberOfBits(BD n, digit nbits);
int spDivideByDigitBD(BD n, digit m, digit * r);
BD spDivideByPowerOfTwo(BD n, digit power);
void spMultiplyByPowerOfTwo(BD n, digit power);
void spShiftToLeftNumberOfDigits(BD n, digit ndigits);
BD spInitWithIntegerBD(signeddigit m);
/*
  Operations with strings and files
 */
char *spStringFromFile(const char *filename, int8_t * sign);
BD spBDFromString(const char *s, int8_t base, int8_t sign);
BD spReadBDFromFile(const char *filename);
char *spBDToString(BD n, digit base);
void spPrintRaw(BD n);
void spPrintDecimal(BD n);
void spPrintBase2(BD n);
void spPrintBytes(BD n);
unsigned char *readFileBinaryMode(const char *filename, size_t * len,
				  size_t * alloc);
int writeFileBinaryMode(const char *filename, unsigned char *data,
			size_t length);
/*
  Addition
 */
int bdCompareAbsoluteValues(BD n1, BD n2);
BD bdAddAbsoluteValues(BD n1, BD n2);
BD bdSubtractAbsoluteValues(BD n1, BD n2, int8_t * sign);
void bdSubtractAbsoluteValuesTo(BD n1, BD n2);
void bdAddAbsoluteValueTo(BD n1, BD n2);
BD bdAddBD(BD n1, BD n2);
int bdAddUnsignedTo(BD n, BD z, size_t pos);
/*
  Subtraction
 */
BD bdSubtractBD(BD n1, BD n2);
int bdSubtractUnsignedTo(BD n, BD z, size_t pos);

/*
  Multiplication
 */
BD karatsuba_simple(BD z0, BD z1, size_t m, size_t ndigits);
BD karatsuba_general(BD z2, BD z, BD z0, size_t m, size_t ndigits);
BD bdMultiplySimpleBD(BD n1, BD n2);
BD bdMultiplyKaratsubaBD(BD n1, BD n2);
BD bdMultiplyBD(BD n1, BD n2);
uint8_t bdMultiplyBDBy(BD * n1, BD n2);
uint8_t bdExponentialBDToPowerOfTwo(BD * n, size_t power);

/*
  Random
 */
BD spRandomBD(size_t nbytes);
unsigned char *randomBytes(size_t nbytes);
uint8_t randomBytesToBuffer(unsigned char *buffer, size_t nbytes);
uint8_t getRandomSalt(unsigned char *salt);

/*
  Division
 */
BD bdDivideSimpleBD(BD n1, BD n2, BD * q);

/*
  Great common divisor
 */
BD bdGCDOfBD(BD n1, BD n2);
BD bdLCMOfBD(BD n1, BD n2);
BD bdExtendedGCDOfBD(BD n1, BD n2, BD * x, BD * y);

/*
  Modular and exponentiation
*/
BD bdMultiplyAndModularBD(BD n1, BD n2, BD n3);
BD bdModularBD(BD n1, BD n2);
uint8_t bdMultiplyAndModularBDBy(BD * n1, BD n2, BD n3);
uint8_t bdExponentialToPowerOfTwoAndModularBD(BD * n, BD n2, size_t power);
BD bdInverseModularBD(BD n1, BD n2, int8_t * error);
BD bdExponentialBD(BD n1, BD n2);
BD bdModExponentialBD(BD n1, BD n2, BD n3);
uint8_t spIsMinusOneBD(BD n1, BD n2);

/*
  Primes
 */
uint8_t spDivisibleByDigit(BD n, digit p);
uint8_t spDivisibleSmallPrime(BD n);
int8_t spRabinMillerTestBD(BD n, size_t iterations);
uint8_t spIsProbablePrime(BD n, size_t iterations);
BD bdRandomPrime(size_t bits);
BD bdStrongRandomPrime(size_t bits);

/*
  RSA
 */
PrivateRSAKey bdInitRSAPrivateKey();
PublicRSAKey bdInitRSAPublicKey();
PrivateRSAKey genRSAPrivateKey(size_t bits);
void spFreeRSAPrivateKey(PrivateRSAKey * r);
void spFreeRSAPublicKey(PublicRSAKey * r);
void spPrintRSAPrivateKey(PrivateRSAKey r);
void spPrintRSAPublicKey(PublicRSAKey r);

/*
  Stack for DER
 */
unsigned char *encode_length(size_t value, size_t * len);
Stack stInitStack();
Stack stInitStackWithSize(size_t size);
void stFreeStack(Stack * st);
int stReInitStackWithSize(Stack st, size_t size);
int stExpandStackInSize(Stack st, size_t size);
void stSetDataInStack(Stack st, unsigned char *data, size_t nbytes,
		      size_t alloc);
size_t stReadLength(Stack st, int *error);
size_t stBytesRemaining(Stack st);
unsigned long long stReadInteger(Stack st, int *error);
unsigned char *stReadOctetString(Stack st, size_t * length, int *error);
unsigned char *stReadBitString(Stack st, size_t * length, int *error);
size_t stReadStartSequenceAndLength(Stack st, int *error);
size_t stReadStartOctetStringAndLength(Stack st, int *error);
size_t stReadStartBitStringAndLength(Stack st, int *error);
int stReadOptionalRsaEncryptionOI(Stack st);
BD stReadBD(Stack st, int *error);
int stWriteNull(Stack st);
int stWriteLength(Stack st, size_t length);
int stWriteInteger(Stack st, unsigned long long integer);
int stWriteOctetString(Stack st, unsigned char *bytes, size_t nbytes);
int stWriteBitString(Stack st, unsigned char *bytes, size_t nbytes);
int stWriteStartSequence(Stack st);
int stWriteStartOctetString(Stack st);
int stWriteStartBitString(Stack st);
int stWriteRsaEncryptionOI(Stack st);
int stWriteBD(Stack st, BD n);

/*
  Compress with zlib
 */
unsigned char *zlib_compress_data(unsigned char *data, size_t insize,
				  size_t * outsize, size_t * alloc);
unsigned char *zlib_uncompress_data(unsigned char *data, size_t insize,
				    size_t * outsize, size_t * alloc);

/*
  Base 64 encoding and decoding
 */
unsigned char *b64_encode(const unsigned char *src, size_t len,
													size_t * out_len);
unsigned char *b64_decode(const unsigned char *src, size_t len,
													size_t * out_len);

/*
  Text to SHA256
 */
void textToSHA256(char *text, unsigned char *sha);
unsigned char *clearCcommentsInText(unsigned char *string,
																		const unsigned char *begin,
																		const unsigned char *end);
/*
  RSA files
 */
unsigned char *readFile(const char *filename, size_t * len);
PrivateRSAKey bdReadPrivateRSAKeyFromFile(const char *filename);
uint8_t bdWritePrivateRSAKeyToFile(const char *filename, PrivateRSAKey rsa);
PrivateRSAKey bdReadEncryptedPrivateRSAKeyFromFile(const char *filename);
uint8_t bdWriteEncryptedPrivateRSAKeyToFile(const char *filename,
																						PrivateRSAKey rsa);
PublicRSAKey bdReadPublicRSAKeyFromFile(const char *filename);
uint8_t bdWritePublicRSAKeyToFile(const char *filename, PublicRSAKey rsa);
int generatePairRSAKeys(int bits, char *filename, int aes);

/*
  Encrypt and decrypt Big Digits
*/
BD publicEncryptRSA(PublicRSAKey rsa, BD m);
BD privateDecryptRSA(PrivateRSAKey rsa, BD c);
BD publicEncryptOAEPRSA(PublicRSAKey rsa, BD m);
BD privateDecryptOAEPRSA(PrivateRSAKey rsa, BD c);
BD privateEncryptOAEPRSA(PrivateRSAKey rsa, BD m);
BD publicDecryptOAEPRSA(PublicRSAKey rsa, BD c);

/*
  Encrypt and decrypt Stack with AES
 */
#define STACKCOMPRESS 1
#define STACKENCODE   2
#define STACKSALT     4
#define ENCRYPTION_OK 0
#define ENCRYPTION_FILE_NOT_FOUND -1
#define ENCRYPTION_WRONG_PASSWORD -2
#define ENCRYPTION_ERROR -3
#define ENCRYPTION_OPEN_FILE_ERROR -4
#define ENCRYPTION_PASSWORD_SHORT -5
#define ENCRYPTION_PUBLIC_KEY_ERROR -6
#define ENCRYPTION_PRIVATE_KEY_ERROR -7
#define ENCRYPTION_WRITE_FILE_ERROR -8
#define SIGNATURE_OK 0
#define SIGNATURE_ERROR -1
#define SIGNATURE_BAD -2
#define SIGNATURE_OPEN_FILE_ERROR -3
#define SIGNATURE_FILE_NOT_FOUND -4

int encryptStackAES(Stack st, PublicRSAKey rsa, unsigned char *salt,
        uint8_t mode);
int decryptStackAES(Stack st, PrivateRSAKey rsa, unsigned char *salt,
        uint8_t mode);

/*
	Encrypt and decrypt files
 */
int encryptFileWithAES(char *infile, char **outfile, int ascii);
int decryptFileWithAES(char *infile, char *outfile);
int encryptFileWithRSA(char *infile, char **outfile, char *keyfile, int ascii);
int decryptFileWithRSA(char *infile, char *outfile, char *keyfile);

/*
  Signatures
*/
int signStackRSA(Stack st,PrivateRSAKey rsa,char *filename,uint8_t mode);
int verifyAndExtractStackRSA(Stack st,PublicRSAKey rsa,uint8_t mode);
int signFileWithRSA(char *infile, char **outfile, char *keyfile, int ascii);
int verifyAndExtractSignedFileWithRSA(char *infile,char *keyfile);

/*
  Password-Based Key Derivation Function 2
 */
int pkcs5_pbkdf2(const char *pass, size_t pass_len, const uint8_t *salt,
		size_t salt_len, uint8_t *key, size_t key_len,
		unsigned int rounds);

/*
  Usefull for debugging
 */
#define SAVEDEBUG(file,data,length) do {                                \
  int _fd_;                                                             \
  if ((_fd_ = open(file,O_WRONLY|O_CREAT|O_TRUNC,S_IRUSR|S_IWUSR)) < 0) \
  {                                                                     \
    printf("Error opening the file %s\n",file);                         \
    goto final;                                                         \
  }                                                                     \
  if ((write(_fd_,data,length) != length))                              \
  {                                                                     \
    printf("Error writing the file %s\n",file);			                    \
    goto final;                                                         \
  }                                                                     \
  close(_fd_);                                                          \
  } while (0);

#endif				/* H_MCERSA_H_ */
