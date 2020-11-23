/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file enrollment.h */
#ifndef CSS_ENROLLMENT_H_
#define CSS_ENROLLMENT_H_

#include "dto.h"
#include "config.h"

#define RSA_DEFAULT_EXP 65537

int cms_job_enroll(struct SessionJob* jobInfo, struct ConfigData* config, \
	char* sessionToken, char** chainJob);

#endif /* ENROLLMENT_H_ */
