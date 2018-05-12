/**************************************************************************************
* Filename:   xmalloc.c
*
* Disclaimer: This file is based on chapter 7 of the book
*
*             Programming Projects in C for Students of
*             Engineering, Science and Mathematics
*             Rouben Rostamian
*             SIAM
*             Computational Science & Engineering (2014)
*             ISBN 978-1-611973-49-5
*             https://userpages.umbc.edu/~rostamia/cbook/
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
#include <stdio.h>
#include <stdlib.h>

void *malloc_or_exit(size_t nbytes, const char *file, int line)
{
	void *x;
	if ((x = calloc(nbytes, 1)) == NULL)
	{
		fprintf(stderr, "%s:line %d: calloc() of %zu bytes failed\n",
						file, line, nbytes);
		exit(EXIT_FAILURE);
	} else
	{
		return x;
	}
}

void *realloc_or_exit(void *v, size_t nbytes, const char *file, int line)
{
	void *x;
	if ((x = realloc(v, nbytes)) == NULL)
	{
		fprintf(stderr, "%s:line %d: realloc() of %zu bytes failed\n",
						file, line, nbytes);
		exit(EXIT_FAILURE);
	} else
	{
		return x;
	}
}
