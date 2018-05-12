/**************************************************************************************
* Filename:   modular.c
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
#include <stdlib.h>
#include <array.h>

BD bdModularBD(BD n1, BD n2)
/*
  The algorithm uses the absolute values of n2

  Returns r = n1 mod (n2)
*/
{
	BD q, r;
	if ((r = bdDivideSimpleBD(n1, n2, &q)) == NULL)
		return NULL;
	freeBD(q);
	if (r->sign == -1)
	{
		q = spCopyBD(n2);
		q->sign = 1;
		bdSubtractAbsoluteValuesTo(q, r);
		freeBD(r);
		return q;
	}
	return r;
}

BD bdMultiplyAndModularBD(BD n1, BD n2, BD n3)
/*
  The algorithm uses the absolute values of n1, n2 and n2

  Returns r = n1 * n2 mod(n3)
*/
{
	BD r, m;
	if ((r = bdMultiplyBD(n1, n2)) == NULL)
		return NULL;
	if ((m = bdModularBD(r, n3)) == NULL)
	{
		freeBD(r);
		return NULL;
	}
	freeBD(r);
	return m;
}

uint8_t bdMultiplyAndModularBDBy(BD * n1, BD n2, BD n3)
/*
  n1 = n1 * n2  mod(n3)
*/
{
	BD m;
	if ((m = bdMultiplyAndModularBD(*n1, n2, n3)) == NULL)
		return 0;
	freeBD(*n1);
	*n1 = m;
	return 1;
}

uint8_t bdExponentialToPowerOfTwoAndModularBD(BD * n, BD n2, size_t power)
/*
  n = n ^ (2 ^ power)  mod(n2)
*/
{
	/*
		Nothing to do
	*/
	if (power == 0)
		return 1;
	if (spIsZeroBD(*n) || spIsOneBD(*n))
		return 1;
	/*
		Start squaring
	*/
	size_t i;
	BD r;
	for (i = 0; i < power; i++)
	{
		if ((r = bdMultiplyAndModularBD(*n, *n, n2)) == NULL)
			return 0;
		freeBD(*n);
		*n = r;
	}
	return 1;
}

BD bdInverseModularBD(BD n1, BD n2, int8_t * error)
/*
  The algorithm uses the absolute values of n1 and n2

  Returns a positive number r such tat n1 * r = 1 modm (n2)
  *error =  0 if OK
	= -1 if n1 and n2 are not coprimes
	= -2 otherwise
*/
{
	BD r, x, y;

	*error = 0;
	if ((r = bdExtendedGCDOfBD(n1, n2, &x, &y)) == NULL)
	{
		*error = -2;
		goto ERRORGCD;
	}
	if (!spIsOneBD(r))
	{
		*error = -1;
		goto ERRORGCD;
	}
	freeBD(y);
	freeBD(r);
	if (x->sign == -1)
	{
		r = spCopyBD(n2);
		r->sign = 1;
		bdSubtractAbsoluteValuesTo(r, x);
		freeBD(x);
		return r;
	}
	return x;

ERRORGCD:
	freeBD(r);
	r = NULL;
	freeBD(x);
	x = NULL;
	freeBD(y);
	y = NULL;
	return NULL;
}

BD bdExponentialBD(BD n1, BD n2)
/*
  The algorithm uses the absolute values of n1 and n2

  Returns n1^n2

  This function uses the Sliding-window exponentiation algorithm
  described in A Handbook Of Applied Cryptography by Alfred . J. Menezes,
  Paul C. van Oorschot and Scott A. Vanstone, pag. 616. with k = 8
*/
{
	/*
		Trivial cases
	*/
	if (spIsZeroBD(n1) && spIsZeroBD(n2))
		return NULL;
	if (spIsZeroBD(n2))
		return spInitWithOneBD();
	if (spIsZeroBD(n1))
		spInitBD();

	int8_t s1, s2;
	s1 = n1->sign;
	n1->sign = 1;
	s2 = n2->sign;
	n2->sign = 1;
	/*
		Precomputation: g[i] = n1^i for i = 0,1,2,3,5,7,.....,255
	*/
	BD *g, r;
	size_t nbit, i;

	r = NULL;
	make_vector(g, 256);
	if ((g[0] = spInitWithOneBD()) == NULL)
		goto FINAL;
	if ((g[1] = spCopyBD(n1)) == NULL)
		goto FINAL;
	if ((g[2] = bdMultiplyBD(g[1], g[1])) == NULL)
		goto FINAL;
	for (i = 1; i < 128; i++)
		if ((g[2 * i + 1] = bdMultiplyBD(g[2 * i - 1], g[2])) == NULL)
			goto FINAL;

	/*
		Example: supose that BITS_PER_DIGIT is 32 and
		n2 = 11000000110110111001 00101001100000010100010110001111 01000100010011000000101000101100 in base 2
		we break n2 as follows
		11 0 0 0 0 0 0 11011011 1001001 0 10011 0 0 0 0 0 0 1010001 0 1100011 11010001 0 0 0 10011 0 0 0 0 0 0 1010001 0 11 0 0
		i. e., every part is 
		0 
		or 
		begins and ends with 1 and has length <= 8

		Then, we start with r = 1 and
		for every part p from left to right we do
		if p = 0 then r = r^2
		otherwise  r = r * g[p]      

	*/
	nbit = spBitsInBD(n2);
	if ((r = spInitWithOneBD()) == NULL)
		goto FINAL;
	while (nbit > 0)
	{
		int8_t bit = spGetBit(n2, nbit - 1);
		size_t obit = nbit;
		if (bit < 0)
		{
			goto FINAL;
		}
		if (bit == 0)
		{
			/*
				Squaring r
			*/
			if (!bdMultiplyBDBy(&r, r))
			{
				freeBD(r);
				r = NULL;
				goto FINAL;
			}
			nbit--;
		} else if (bit == 1)
		{
			size_t ndigit;
			uint8_t index;
			digit m, mask;
			ndigit =
				(nbit + BITS_PER_DIGIT - 1) / BITS_PER_DIGIT;
			i = nbit % BITS_PER_DIGIT;
			if (i == 0)
				i = BITS_PER_DIGIT;
			m = n2->digits[ndigit - 1];
			if (i >= 8)
			{
				nbit -= 8;
				mask = (digit) 255 << (i - 8);
				index = (uint8_t) ((m & mask) >> (i - 8));
			} else
			{
				mask = (((digit) 1 << i) - 1);
				index = (uint8_t) ((m & mask));
				if (ndigit == 1)
				{
					nbit -= i;
				} else
				{
					nbit -= 8;
					m = n2->digits[ndigit - 2];
					mask =
						~(((digit) 1 <<
							 (BITS_PER_DIGIT -
								(8 - i))) - 1);
					index =
						(index << (8 - i)) |
						(uint8_t) ((m & mask) >>
											 (BITS_PER_DIGIT -
												(8 - i)));
				}
			}
			while ((index % 2) == 0)
			{
				index /= 2;
				nbit++;
			}
			/*
				r = r ^ (2 ^ (onit - nbit))
			*/
			if (!bdExponentialBDToPowerOfTwo(&r, obit - nbit))
			{
				freeBD(r);
				r = NULL;
				goto FINAL;
			}
			/*
				r = r * g[index]
			*/
			if (!bdMultiplyBDBy(&r, g[index]))
			{
				freeBD(r);
				r = NULL;
				goto FINAL;
			}
		}
	}
FINAL:
	n1->sign = s1;
	n2->sign = s2;
	for (i = 0; i < 256; i++)
		freeBD(g[i]);
	free_vector(g);

	return r;
}

BD bdModExponentialBD(BD n1, BD n2, BD n3)
/*
  The algorithm uses the absolute values of n1, n2 and n3

  Returns r = n1^n2 mod(n3)

  Is the same algorithm than bdExponentialBD, but now after ever multiplication,
  we take modulus n3
*/
{
	if (spIsZeroBD(n3))
		return NULL;
	if (spIsZeroBD(n1) && spIsZeroBD(n2))
		return NULL;
	if (spIsZeroBD(n2))
		return spInitWithOneBD();
	if (spIsZeroBD(n1))
		spInitBD();

	int8_t s1, s2, s3;
	s1 = n1->sign;
	n1->sign = 1;
	s2 = n2->sign;
	n2->sign = 1;
	s3 = n2->sign;
	n3->sign = 1;
	/*
		Precomputation: g[i] = n1^i mod (n3)  for i = 0,1,2,3,5,7,.....,255
	*/
	BD *g, r;
	size_t nbit, i;

	r = NULL;
	make_vector(g, 256);
	if ((g[0] = spInitWithOneBD()) == NULL)
		goto FINAL;
	if ((g[1] = bdModularBD(n1, n3)) == NULL)
		goto FINAL;
	if ((g[2] = bdMultiplyAndModularBD(g[1], g[1], n3)) == NULL)
		goto FINAL;
	for (i = 1; i < 128; i++)
		if ((g[2 * i + 1] =
		     bdMultiplyAndModularBD(g[2 * i - 1], g[2], n3)) == NULL)
			goto FINAL;

	nbit = spBitsInBD(n2);
	if ((r = spInitWithOneBD()) == NULL)
		goto FINAL;
	while (nbit > 0)
	{
		int8_t bit = spGetBit(n2, nbit - 1);
		size_t obit = nbit;
		if (bit < 0)
		{
			goto FINAL;
		}
		if (bit == 0)
		{
			/*
				Squaring and modulus: r = r^2 mod(n3);
			*/
			if (!bdMultiplyAndModularBDBy(&r, r, n3))
			{
				freeBD(r);
				r = NULL;
				goto FINAL;
			}
			nbit--;
		} else if (bit == 1)
		{
			size_t ndigit;
			uint8_t index;
			digit m, mask;
			ndigit =
				(nbit + BITS_PER_DIGIT - 1) / BITS_PER_DIGIT;
			i = nbit % BITS_PER_DIGIT;
			if (i == 0)
				i = BITS_PER_DIGIT;
			m = n2->digits[ndigit - 1];
			if (i >= 8)
			{
				nbit -= 8;
				mask = (digit) 255 << (i - 8);
				index = (uint8_t) ((m & mask) >> (i - 8));
			} else
			{
				mask = (((digit) 1 << i) - 1);
				index = (uint8_t) ((m & mask));
				if (ndigit == 1)
				{
					nbit -= i;
				} else
				{
					nbit -= 8;
					m = n2->digits[ndigit - 2];
					mask =
						~(((digit) 1 <<
							 (BITS_PER_DIGIT -
								(8 - i))) - 1);
					index =
						(index << (8 - i)) |
						(uint8_t) ((m & mask) >>
											 (BITS_PER_DIGIT -
												(8 - i)));
				}
			}
			while ((index % 2) == 0)
			{
				index /= 2;
				nbit++;
			}
			/*
				r = r ^ (2 ^ (onit - nbit))  mod (n3)
			*/
			if (!bdExponentialToPowerOfTwoAndModularBD
					(&r, n3, obit - nbit))
			{
				freeBD(r);
				r = NULL;
				goto FINAL;
			}
			/*
				r = r * g[index] and take modulus n3
			*/
			if (!bdMultiplyAndModularBDBy(&r, g[index], n3))
			{
				freeBD(r);
				r = NULL;
				goto FINAL;
			}
		}
	}
FINAL:
	n1->sign = s1;
	n2->sign = s2;
	n3->sign = s3;
	for (i = 0; i < 256; i++)
		freeBD(g[i]);
	free_vector(g);

	return r;
}

uint8_t spIsMinusOneBD(BD n1, BD n2)
/*
  The algorithm uses the absolute values of n1, n2
  
  Returns 1 if n2 == n1 - 1
	0 otherwise 
*/
{
	size_t i;
	if (n1->used != n2->used)
		return 0;
	for (i = 1; i < n1->used; i++)
		if (n1->digits[i] != n2->digits[i])
			return 0;
	return (n1->digits[0] == (n2->digits[0] + 1));
}
