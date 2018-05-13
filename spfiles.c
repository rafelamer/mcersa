/**************************************************************************************
* Filename:   spfiles.c
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
#include <mcersa.h>
#include <array.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

static const char *spDigits =
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

char *spStringFromFile(const char *filename, int8_t * sign)
{
	FILE *fp;
	if ((fp = fopen(filename, "r")) == NULL)
		return NULL;
	int c;
	/*
		Discard initial spaces
	*/
	do
	{
		c = getc(fp);
	}
	while (isspace(c));
	/*
		Sign
	*/
	*sign = 1;
	if (c == '+')
	{
		*sign = 1;
		c = getc(fp);
	} else if (c == '-')
	{
		*sign = -1;
		c = getc(fp);
	}
	/*
		Discard more spaces
	*/
	while (isspace(c))
		c = getc(fp);
	/*
		Dircard initial zeros
	*/
	while (c == '0')
		c = getc(fp);
	/*
		Read discarding non-digits
	*/
	char *str;
	size_t alloc_size, str_size;
	alloc_size = 256;
	str_size = 0;
	make_vector(str, alloc_size);
	while (c != EOF)
	{
		if (!isdigit(c))
		{
			c = getc(fp);
			continue;
		}
		if (str_size == alloc_size)
		{
			alloc_size = alloc_size * 3 / 2;
			expand_vector(str, alloc_size);
		}
		str[str_size++] = c;
		c = getc(fp);
	}
	fclose(fp);
	if (str_size == alloc_size)
	{
		alloc_size += 1;
		expand_vector(str, alloc_size);
	}
	str[str_size] = '\0';
	return str;
}

BD spBDFromString(const char *s, int8_t base, int8_t sign)
{
	BD n;
	size_t i;
	digit j;
	size_t nchars = strlen(s);

	if ((n = spInitBD()) == NULL)
		return NULL;

	n->sign = sign;
	for (i = 0; i < nchars; i++)
	{
		char ch = s[i];
		for (j = 0; j < base; j++)
			if (spDigits[j] == ch)
				break;
		spMultiplyByDigitBD(n, base);
		spAddDigitToBD(n, j, 0);
	}
	return n;
}

BD spReadBDFromFile(const char *filename)
{
	char *s;
	int8_t sign;
	BD n;
	if ((s = spStringFromFile(filename, &sign)) == NULL)
		return NULL;
	n = spBDFromString(s, 10, sign);
	free_vector(s);
	return n;
}

void spReverseString(char *s, size_t len)
{
	char *p, *q, t;
	p = s;
	q = s + (len - 1);
	while (q > p)
	{
		t = *q;
		*q-- = *p;
		*p++ = t;
	}
}

char *spBDToString(BD n, digit base)
{
	BD aux;
	char *s;
	digit r;

	if ((base < 2) || (base > 64))
		return NULL;

	if (spSizeOfBD(n) == 0)
	{
		make_vector(s, 2);
		s[0] = '0';
		s[1] = '\0';
		return s;
	}
	size_t allocSize = 1024;
	size_t strSize = 0;

	make_vector(s, allocSize);
	if ((aux = spCopyBD(n)) == NULL)
		return NULL;
	while (spSizeOfBD(aux) > 0)
	{
		if (spDivideByDigitBD(aux, base, &r) < 0)
		{
			free_vector(s);
			return NULL;
		}
		if (strSize == allocSize)
		{
			allocSize = allocSize * 3 / 2;
			expand_vector(s, allocSize);
		}
		s[strSize++] = spDigits[r];
	}
	if ((allocSize - strSize) < 2)
	{
		allocSize += 2;
		expand_vector(s, allocSize);
	}
	if (n->sign == -1)
		s[strSize++] = '-';
	s[strSize] = '\0';
	spReverseString(s, strSize);
	freeBD(aux);
	return s;
}

void spPrintRaw(BD n)
{
	size_t i;
	for (i = 0; i < n->used; i++)
		printf("%llu\n", n->digits[i]);
	printf("\n");
}

void spPrintDecimal(BD n)
{
	char *s;
	s = spBDToString(n, 10);
	printf("%s\n", s);
	free_vector(s);
	printf("\n");
}

void spPrintBase2(BD n)
{
	char *s;
	s = spBDToString(n, 2);
	printf("%s\n", s);
	free_vector(s);
	printf("\n");
}

void spPrintBytes(BD n)
{
	unsigned char *p;
	size_t nbytes, i;
	nbytes = spBytesInBD(n);
	p = (unsigned char *)(n->digits);
	for (i = 0; i < nbytes; i++)
		printf("%02X ", *p++);
	printf("\n");
}

unsigned char *readFileBinaryMode(const char *filename, size_t * len,
																	size_t * alloc)
/*
  Reads the contents of the file and returns it in a vector of unsiged chars. The size
  of the file, i.e., the numbers of bytes read is stored in *len.
*/
{
	int fd;

	if ((fd = open(filename, O_RDONLY)) < 0)
		return NULL;

	unsigned char *str;
	unsigned char buffer[4096];
	int n;

	str = NULL;
	*alloc = 4096;
	*len = 0;
	if ((str = (unsigned char *)calloc(*alloc,sizeof(unsigned char))) == NULL)
		return NULL;

	while ((n = read(fd, buffer, 4096)) > 0)
	{
		if ((*alloc - *len) < n)
		{
			*alloc += (*alloc * 4) / 3;
			if ((str = (unsigned char *)realloc(str,*alloc * sizeof(unsigned char))) == NULL)
				return NULL;
		}
		memcpy(str + *len, buffer, n);
		*len += n;
	}
	close(fd);
	if (n < 0)
	{
		free(str);
		str = NULL;
		*len = 0;
		*alloc = 0;
		return NULL;
	}
	return str;
}

int writeFileBinaryMode(const char *filename, unsigned char *data,
												size_t length)
{
	int fd;

	if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR)) < 0)
		return 0;

	if (write(fd, data, length) != length)
	{
		close(fd);
		unlink(filename);
		return 0;
	}
	close(fd);
	return 1;
}
