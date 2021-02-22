/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file management.h */
#include "dto.h"
#include "config.h"

/**
 * The management job flow:
 * 		1.) Ask the platform for the details on the managment job (get config)
 *		2.) Based on the response:
 *				a.) If the job was canceled, you finish
 *				b.) If the job was an ADD, run the ADD workflow
 *				c.) If the job was a REMOVE, run the REMOVE workflow
 *		3.) Respond to the platform as to the job's success
 *
 * @param  - [Input] : jobInfo
 * @param  - [Input] : sessionToken
 * @param  - [Input] : chainJob
 * @return - job was run : 0
 *		   - job was canceled : 1
 */
int cms_job_manage(struct SessionJob* jobInfo, char* sessionToken, char** chainJob);
