/******************************************************************************/
/* Copyright 2021 Keyfactor                                                   */
/* Licensed under the Apache License, Version 2.0 (the "License"); you may    */
/* not use this file except in compliance with the License.  You may obtain a */
/* copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless */
/* required by applicable law or agreed to in writing, software distributed   */
/* under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES   */
/* OR CONDITIONS OF ANY KIND, either express or implied. See the License for  */
/* thespecific language governing permissions and limitations under the       */
/* License.                                                                   */
/******************************************************************************/

#ifndef OPENSSL_COMPAT_H_
#define OPENSSL_COMPAT_H_

#ifndef __WOLF_SSL__
#if OPENSSL_VERSION_NUMBER < 0x10100000L
void RSA_get0_key(const RSA* r, const BIGNUM** n, const BIGNUM** e, 
	const BIGNUM**d)
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
#endif /* OPENSSL_VERSION_NUMBER */
#endif /* __WOLF_SSL__ */

#endif /* OPENSSL_COMPAT_H_ */
