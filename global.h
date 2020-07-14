/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
/***************************************************************************//**
 @file global.h
  Global header file for things like global defines, variables, etc.
  History:
      2019-Nov-07 R.Lillback Created initial version
      2020-Jul-14 R.Lillback Added HTTP version switch
 */

#ifndef _GLOBAL_H_
#define _GLOBAL_H_

/* Undefine this for HTTP version 2.0 */
#define __HTTP_1_1__

#undef __DEBUG__
#undef __PLATFORM_FIXED__

#ifdef __TPM__
extern char *engine_id;
#endif

#endif
