/**************************************************************************************
* Filename:   rsa.c
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

PrivateRSAKey bdInitRSAPrivateKey()
{
	PrivateRSAKey rsa;
	rsa = NULL;
	if ((rsa = (PrivateRSAKey) malloc(sizeof(private_rsa_key))) == NULL)
		goto errorRSA;
	if ((rsa->pub = (PublicRSAKey) malloc(sizeof(public_rsa_key))) == NULL)
		goto errorRSA;
	rsa->pub->n = NULL;
	rsa->pub->ek = NULL;
	rsa->dk = NULL;
	rsa->p = NULL;
	rsa->q = NULL;
	rsa->kp = NULL;
	rsa->kq = NULL;
	rsa->c2 = NULL;
	return rsa;

 errorRSA:
	freePrivateRSAKey(rsa);
	return NULL;
}

PublicRSAKey bdInitRSAPublicKey()
{
	PublicRSAKey rsa;
	rsa = NULL;

	if ((rsa = (PublicRSAKey) malloc(sizeof(public_rsa_key))) == NULL)
		return NULL;
	rsa->n = NULL;
	rsa->ek = NULL;
	return rsa;
}

PrivateRSAKey genRSAPrivateKey(size_t bits)
{
	PrivateRSAKey rsa;
	rsa = NULL;
	BD p, q, n, e, d, phi, ek, dk, c2, kp, kq;
	p = q = n = e = d = phi = ek = dk = c2 = kp = kq = NULL;
	int8_t error;

	if (bits < 1024)
		bits = 1024;

	if ((rsa = (PrivateRSAKey) malloc(sizeof(private_rsa_key))) == NULL)
		goto errorRSA;
	if ((rsa->pub = (PublicRSAKey) malloc(sizeof(public_rsa_key))) == NULL)
		goto errorRSA;
	if ((p = bdStrongRandomPrime(bits / 2)) == NULL)
		goto errorRSA;
	if ((q = bdStrongRandomPrime(bits / 2)) == NULL)
		goto errorRSA;
	if ((n = bdMultiplyBD(p, q)) == NULL)
		goto errorRSA;
	if ((e = spCopyBD(p)) == NULL)
		goto errorRSA;
	if ((d = spCopyBD(q)) == NULL)
		goto errorRSA;
	spSubtractDigitToBD(e, (digit) 1);	// e = p - 1
	spSubtractDigitToBD(d, (digit) 1);	// d = q - 1

	if ((phi = bdLCMOfBD(e, d)) == NULL)	// phi = lcm(p - 1,q - 1)
		goto errorRSA;

	/*
	   Encryption key ek and decription key dk
	 */
	if ((ek = spInitWithIntegerBD(65537)) == NULL)
		goto errorRSA;
	for (;;)
	  {
		  dk = bdInverseModularBD(ek, phi, &error);
		  if (error == 0)
			  break;
		  if (error == -1)
			  spAddDigitToBD(ek, (digit) 1, 0);
		  else
			  goto errorRSA;
	  }
	/*
	   c2 = q^(-1) mod (p)
	 */
	if ((c2 = bdInverseModularBD(q, p, &error)) == NULL)
		goto errorRSA;

	/*
	   Numbers kp and kq
	 */
	if ((kp = bdModularBD(dk, e)) == NULL)
		goto errorRSA;
	if ((kq = bdModularBD(dk, d)) == NULL)
		goto errorRSA;

	/*
	   Set numbers in rsa
	 */
	freeBD(e);
	e = NULL;
	freeBD(d);
	d = NULL;
	freeBD(phi);
	phi = NULL;
	rsa->pub->n = n;
	rsa->pub->ek = ek;
	rsa->p = p;
	rsa->q = q;
	rsa->dk = dk;
	rsa->kp = kp;
	rsa->kq = kq;
	rsa->c2 = c2;
	return rsa;

 errorRSA:
	freePrivateRSAKey(rsa);
	freeBD(p);
	freeBD(q);
	freeBD(n);
	freeBD(e);
	freeBD(d);
	freeBD(phi);
	freeBD(ek);
	freeBD(dk);
	freeBD(c2);
	return NULL;
}

void spPrintRSAPrivateKey(PrivateRSAKey r)
{
	printf("n = ");
	spPrintDecimal(r->pub->n);
	printf("ek = ");
	spPrintDecimal(r->pub->ek);
	printf("p = ");
	spPrintDecimal(r->p);
	printf("q = ");
	spPrintDecimal(r->q);
	printf("dk = ");
	spPrintDecimal(r->dk);
	printf("dk mod (p - 1) = kp = ");
	spPrintDecimal(r->kp);
	printf("dk mod (q - 1) = kq = ");
	spPrintDecimal(r->kq);
	printf("q^(-1) mod (p) = c2 = ");
	spPrintDecimal(r->c2);
}

void spPrintRSAPublicKey(PublicRSAKey r)
{
	printf("n = ");
	spPrintDecimal(r->n);
	printf("ek = ");
	spPrintDecimal(r->ek);
}

void spFreeRSAPrivateKey(PrivateRSAKey * r)
{
	if (*r == NULL)
		return;
	freeBD((*r)->p);
	freeBD((*r)->q);
	freeBD((*r)->dk);
	freeBD((*r)->kp);
	freeBD((*r)->kq);
	freeBD((*r)->c2);
	freeBD((*r)->pub->n);
	freeBD((*r)->pub->ek);
	free((*r)->pub);
	free(*r);
	*r = NULL;
}

void spFreeRSAPublicKey(PublicRSAKey * r)
{
	if (*r == NULL)
		return;
	freeBD((*r)->n);
	freeBD((*r)->ek);
	free(*r);
	*r = NULL;
}
