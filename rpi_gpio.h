/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#ifndef __RPI_GPIO_H__
#define __RPI_GPIO_H__

/* function prototypes */
int setup_io( void );
void cleanup_io( void );
void turn_on_led( void );
void turn_off_led( void );

/* global defines */


#endif
