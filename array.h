/**************************************************************************************
* Filename:   array.h
* 
* Disclaimer: This file is based on chapter 8 of the book
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
#ifndef H_ARRAY_H
#define H_ARRAY_H 1

#include <string.h>
#include <stdlib.h>

#define FREE_APPENDED 1
#define NOT_FREE_APPENDED 0

#define xmalloc(nbytes) malloc_or_exit((nbytes), __FILE__, __LINE__)
#define xrealloc(vector,nbytes) realloc_or_exit((vector),(nbytes), __FILE__, __LINE__)

void *malloc_or_exit(size_t nbytes, const char *file, int line);
void *realloc_or_exit(void *v, size_t nbytes, const char *file, int line);

#define make_vector(v,n) ((v) = xmalloc((n) * sizeof(*(v))))

#define free_vector(v) do { free(v); v = NULL; } while (0)

#define clone_vector(u,v,n) do {                              \
      make_vector(v,(n));                                     \
      memcpy(v,(u),(n)*sizeof(*(u)));                         \
} while (0)

#define append_to_vector(u,v,m,n,f) do {                      \
    if ((u) == NULL)                                          \
      (u) = xmalloc((n) * sizeof(*(u)));                      \
    else                                                      \
      (u) = xrealloc((u),((m)+(n)) * sizeof(*(u)));           \
    void *p = u + m;                                          \
    memcpy(p,(v),(n)*sizeof(*(v)));                           \
    if((f))                                                   \
       free_vector((v));                                      \
} while (0)

#define expand_vector(v,n) ((v) = xrealloc((v),(n) * sizeof(*(v))))

#define make_matrix(a, m, n) do {                             \
    make_vector(a, (m) + 1);                                  \
    for (size_t make_matrix_loop_counter = 0;                 \
         make_matrix_loop_counter < (m);                      \
         make_matrix_loop_counter++)                          \
         make_vector((a)[make_matrix_loop_counter], (n));     \
    (a)[m] = NULL;                                            \
} while (0)

#define clone_matrix(u,v,m,n) do {		              \
    make_matrix(v,(m),(n));                                   \
    for (size_t make_matrix_loop_counter = 0;                 \
	 make_matrix_loop_counter < (m);                      \
         make_matrix_loop_counter++)                          \
         memcpy(v[make_matrix_loop_counter],                  \
                u[make_matrix_loop_counter],                  \
		(n)*sizeof(**(v)));                           \
} while (0)

#define free_matrix(a) do {                                   \
    if (a != NULL) {                                          \
        for (size_t make_matrix_loop_counter = 0;             \
             (a)[make_matrix_loop_counter] != NULL;           \
             make_matrix_loop_counter++)                      \
            free_vector((a)[make_matrix_loop_counter]);       \
        free_vector(a);                                       \
        a = NULL;                                             \
    }                                                         \
} while (0)

#define make_triangular_matrix(a, n) do {                     \
    make_vector(a, (n) + 1);                                  \
    for (size_t make_matrix_loop_counter = 0;                 \
         make_matrix_loop_counter < (n);                      \
         make_matrix_loop_counter++)                          \
         make_vector((a)[make_matrix_loop_counter],           \
	   (n) - make_matrix_loop_counter );		      \
    (a)[n] = NULL;                                            \
} while (0)

#define matrix_to_vector(a,v,m,n,type) do {                    \
    type *matrix_vector_pointer;                               \
    matrix_vector_pointer = v;			               \
    for (size_t matrix_vector_loop_counter = 0;                \
                matrix_vector_loop_counter < (n);              \
	        matrix_vector_loop_counter++) {		       \
      memcpy(matrix_vector_pointer,                            \
	     a[matrix_vector_loop_counter],(n)*sizeof(type));  \
      matrix_vector_pointer += (n);                            \
    }	           		                               \
} while (0)

#define vector_to_matrix(v,a,m,n,type) do {                    \
    type *vector_matrix_pointer;                               \
    vector_matrix_pointer = v;			               \
    for (size_t vector_matrix_loop_counter = 0;                \
                vector_matrix_loop_counter < (m);              \
	        vector_matrix_loop_counter++) {		       \
      memcpy(a[vector_matrix_loop_counter],                    \
	     vector_matrix_pointer,(n)*sizeof(type));          \
      vector_matrix_pointer += (n);                            \
    }	           		                               \
} while (0)

#define print_vector(fmt, v, n) do {                        \
    for (size_t print_vector_loop_counter = 0;              \
                print_vector_loop_counter < (n);            \
                print_vector_loop_counter++)                \
        printf(fmt, (v)[print_vector_loop_counter]);        \
    putchar('\n');                                          \
} while (0)

#define print_matrix(fmt, a, m, n) do {                         \
    for (size_t print_matrix_loop_counter = 0;                  \
                print_matrix_loop_counter < (m);                \
                print_matrix_loop_counter++)                    \
        print_vector(fmt, (a)[print_matrix_loop_counter], (n)); \
} while (0)

#endif				/*  H_ARRAY_H */
