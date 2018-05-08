/**************************************************************************************
* Filename:   subtraction.c
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

BD bdSubtractBD(BD n1, BD n2)
/*
  Returns n1 - n2
 */
{
	int8_t sign;
	BD n;

	sign = n1->sign * n2->sign;
	/*
	   n1 and n2 with diferent sign
	 */
	if (sign == -1)
	  {
		  n = bdAddAbsoluteValues(n1, n2);
		  n->sign = n1->sign;
		  return n;
	  }
	/*
	   n1 and n2 with the same sign
	 */
	if (sign == 1)
	  {
		  n = bdSubtractAbsoluteValues(n1, n2, &sign);
		  n->sign = n1->sign * sign;
		  return n;
	  }
	return NULL;
}

int bdSubtractUnsignedTo(BD n, BD z, size_t pos)
/*
  Computes n = n - z*B^pos
  Returns: 0 if OK
          -1 if n can't contain the result
 */
{
	digit t;
	size_t i;
	t = 0;
	for (i = 0; i < z->used; i++)
	  {
		  if (i + pos >= n->alloc)
			  return -1;
		  t = spSubtractTo(n->digits + i + pos, z->digits[i], t);
		  if (i + pos >= n->used)
			  n->used = i + pos + 1;
	  }
	i = z->used;
	while (t > 0)
	  {
		  if (i + pos >= n->alloc)
			  return -1;
		  t = spSubtractTo(n->digits + i + pos, 0, t);
		  if (i + pos >= n->used)
			  n->used = i + pos + 1;
		  i++;
	  }
	return 0;
}
