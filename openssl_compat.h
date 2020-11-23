/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file openssl_compat.h */
#ifndef CSS_OPENSSL_COMPAT_H_
#define CSS_OPENSSL_COMPAT_H_

#ifndef __WOLF_SSL__
#if OPENSSL_VERSION_NUMBER < 0x10100000L
void RSA_get0_key(const RSA* r, const BIGNUM** n, const BIGNUM** e, const BIGNUM**d)
{
	if(n != NULL)
	{
		*n = r->n;
	}
	if(e != NULL)
	{
		*e = r->e;
	}
	if(d != NULL)
	{
		*d = r->d;
	}
}
#endif // OPENSSL_VERSION_NUMBER
#endif // __WOLF_SSL__

#endif // CSS_OPENSSL_COMPAT_H_
