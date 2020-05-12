/***************************************************************************//**
 @file global.h
  Global header file for things like global defines, variables, etc.
  History:
      2019-Nov-07 R.Lillback Created initial version
 */

#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#undef __DEBUG__
#undef __PLATFORM_FIXED__

#ifdef __TPM__
extern char *engine_id;
#endif

#endif
