/*
This C Agent Reference Implementation uses the OpenSSL encryption libraries, 
which are not included as a part of this distribution.  For hardware key storage 
or TPM support, libraries such as WolfSSL may also be used in place of OpenSSL.

NOTE: usage of this file and the SDK is subject to the 
following SOFTWARE DEVELOPMENT KIT LICENSE: 

THIS IS A LICENSE AGREEMENT between you and Certified Security Solutions, Inc.,
 6050 Oak Tree Boulevard, Suite 450, Independence, Ohio 44131 (“CSS”).  This 
 License Agreement accompanies the Software Development Kit(s) (“SDK,” as 
 defined below) for CSS Products (defined below) licensed to you by CSS.  This 
 copy of the SDK is licensed to You as the end user or the representative of 
 your employer.  You represent that CSS, a licensee of one or more CSS Products
 , or a third-party working on behalf of such a licensee has authorized you to
 download this SDK.  YOU AGREE THAT THIS LICENSE AGREEMENT IS ENFORCEABLE AND 
 THAT YOUR USE OF THE SDK CONSTITUTES ACCEPTANCE OF THE AGREEMENT TERMS.  If 
 you do not agree to the terms of this Agreement, do not use this SDK.  
1. DEFINITIONS.
In this License Agreement: 
(a) “SDK” means the CSS software development kit, including any sample code, 
tools, utilities, documentation, and related explanatory materials and 
includes any upgrades, modified versions, updates, additions, and copies of 
the SDK;  
(b) “CSS Products” means[ CSS’s CMS application programs, technologies and 
software, including but not limited to CMS Enterprise, CMS Sapphire, CMS 
Topaz, and CMS VerdeTTo,] that are or may be made available for licensing, 
including any modified versions or upgrades thereof.  This License Agreement
 does not govern use of CSS Products, which are governed by separate written
 license agreements; and
(c) “You” and “your” refer to any person or entity acquiring or using the 
SDK under the terms of this License Agreement.
2. ROYALTY-FREE DEVELOPMENT LICENSE. Subject to the restrictions contained 
in this Section 2, CSS grants you limited a nonexclusive, nontransferable, 
royalty-free license to use the items in the SDK only for the purpose of 
development of software designed to interoperate with licensed CSS Products 
either on Your own behalf or on behalf of a licensee of one or more CSS
 Products.
(a) Under this License Agreement, you may use, modify, or merge all or 
portions of any sample code included in the SDK with your software .  Any 
modified or merged portion of sample code is subject to this License 
Agreement.  You are required to include CSS’s copyright notices in your 
software. You may make a reasonable, limited number of copies of the SDK to 
be used by your employees or contractors as provided herein, and not for 
general business purposes, and such employees or contractors shall be 
subject to the obligations and restrictions in this License Agreement.  
Except in accordance with the preceding sentence, you may not assign, 
sublicense, or otherwise transfer your rights or obligations granted under 
this License Agreement without the prior written consent of CSS. Any 
attempted assignment, sublicense, or transfer without such prior written 
consent shall be void and of no effect.  CSS may assign or transfer this 
License Agreement in whole or in part, and it will inure to the benefit of 
any successor or assign of CSS.
(b) Under this License Agreement, if you use, modify, or merge all or 
portions of any sample code included in the SDK with your software, you may
distribute it as part of your products solely on a royalty-free 
non-commercial basis.  Any right to distribute any part of the SDK or any 
modified, merged, or derivative version on a royalty-bearing or other 
commercial basis is subject to separate approval, and possibly the 
imposition of a royalty, by CSS.
(c) Except as expressly permitted in paragraphs 2(a) and 2(b), you may not
 sell, sublicense, rent, loan, or lease any portion of the SDK to any third
 party. You may not decompile, reverse engineer, or otherwise access or 
 attempt to access the source code for any part of the SDK not made
 available to you in source code form, nor make or attempt to make any
 modification to the SDK or remove, obscure, interfere with, or circumvent 
 any feature of the SDK, including without limitation any copyright or 
 other intellectual property notices, security, or access control mechanism.
 
3. PROPRIETARY RIGHTS. The items contained in the SDK are the intellectual
 property of CSS and are protected by United States and international 
 copyright and other intellectual property law. You agree to protect all 
 copyright and other ownership interests of CSS  in all items in the SDK 
 supplied to you under this License Agreement. You agree that all copies 
 of the items in the SDK, reproduced for any reason by you, will contain 
 the same copyright notices, and other proprietary notices as appropriate,
 as appear on or in the master items delivered by CSS in the SDK. CSS 
 retains title and ownership of the items in the SDK, the media on which 
 it is recorded, and all subsequent copies, regardless of the form or media
 in or on which the original and other copies may exist.  You may use CSS’s
 trade names, trademarks and service marks only as may be required to 
 accurately describe your products and to provide copyright notice as 
 required herein.
Except as expressly granted above, this License Agreement does not grant 
you any rights under any patents, copyrights, trade secrets, trademarks or 
any other rights in respect to the items in the SDK.
4. FEEDBACK. You are encouraged to provide CSS with comments, bug reports, 
feedback, enhancements, or modifications proposed or suggested by you for 
the SDK or any CSS Product (“Feedback”). If provided, CSS will treat such 
Feedback as non-confidential notwithstanding any notice to the contrary you 
may include in any accompanying communication, and CSS shall have the right
 to use such Feedback at its discretion, including, but not limited to, the
 incorporation of such suggested changes into the SDK or any CSS Product. 
 You hereby grant CSS a perpetual, irrevocable, transferable, sublicensable,
 royalty-free, worldwide, nonexclusive license under all rights necessary to
 so incorporate and use your Feedback for any purpose, including to make 
 and sell products and services.  
5. TERM. This License Agreement is effective until terminated.  CSS has 
the right to terminate this License Agreement immediately, without judicial
 intervention, if you fail to comply with any term herein. Upon any such
 termination you must remove all full and partial copies of the items in 
 the SDK from your computer and discontinue the use of the items in the 
 SDK.
6. DISCLAIMER OF WARRANTY. CSS licenses the SDK to you on an “AS-IS” basis.
 CSS makes no representation with respect to the adequacy of any items in
 the SDK, whether or not used by you in the development of any products, 
 for any particular purpose or with respect to their adequacy to produce 
 any particular result. CSS shall not be liable for loss or damage arising
 out of this License Agreement or from the distribution or use of your 
 products containing portions of the SDK. TO THE FULLEST EXTENT PERMITTED 
 BY LAW, CSS DISCLAIMS ALL WARRANTIES, EITHER EXPRESS OR IMPLIED, INCLUDING
 BUT NOT LIMITED TO IMPLIED CONDITIONS OR WARRANTIES OF MERCHANTABILITY AND
 FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT OF ANY THIRD PARTY 
 RIGHT IN RESPECT OF THE ITEMS IN THE SDK.
CSS is under no obligation to provide any support under this License 
Agreement, including upgrades or future versions of the SDK or any portions
 thereof, to you, any end user or to any other party. 
7. LIMITATION OF LIABILITY. Notwithstanding any other provisions of this 
License Agreement, CSS’s liability to you under this License Agreement 
shall be limited to the amount you paid for the SDK or $10, whichever is 
less.
IN NO EVENT WILL CSS BE LIABLE TO YOU FOR ANY CONSEQUENTIAL, INDIRECT, 
INCIDENTAL, PUNITIVE, OR SPECIAL DAMAGES, INCLUDING DAMAGES FOR ANY LOST 
PROFITS, LOST SAVINGS, LOSS OF DATA, COSTS, FEES OR EXPENSES OF ANY KIND OR
 NATURE, ARISING OUT OF ANY PROVISION OF THIS LICENSE AGREEMENT OR THE USE
 OR INABILITY TO USE THE ITEMS IN THE SDK, EVEN IF A CSS REPRESENTATIVE HAS
 BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES, OR FOR ANY CLAIM BY ANY 
 PARTY. 
8. INDEMNIFICATION. You agree to indemnify, hold harmless, and defend CSS
 from and against any claims or lawsuits, including attorneys’ fees, that 
 arise or result from the use and distribution of your products that 
 contain or are based upon any portion of the SDK, provided that CSS gives
 you prompt written notice of any such claim, tenders the defense or 
 settlement of such a claim to you at your expense, and cooperates with 
 you, at your expense, in defending or settling any such claim.
9. CHOICE OF LAW. This Agreement will be governed by and construed in 
accordance with the substantive laws of the United States and the State of
 Ohio.  Federal and state courts located in Cuyahoga County, Ohio shall 
 have exclusive jurisdiction over all disputes relating to this Agreement.
 This Agreement will not be governed by the conflict of law rules of any 
 jurisdiction or the United Nations Convention on Contracts for the 
 International Sale of Goods, the application of which is expressly 
 excluded.
10. COMPLIANCE WITH EXPORT CONTROL LAWS. You agree that any of your 
products that include any part of the SDK will not be shipped, transferred
 or exported into any country or used in any manner prohibited by the 
 United States Export Administration Act and that you will comply with 
 all applicable export control laws. All rights to use the SDK are granted 
 on condition that such rights are forfeited if you fail to comply with the
 terms of this Agreement.
11. NON-BLOCKING OF CSS DEVELOPMENT. You acknowledge that CSS is currently 
developing or may develop technologies and products in the future that have
 or may have design and/or functionality similar to products that you may
 develop based on your license herein. Nothing in this Agreement shall
 impair, limit or curtail CSS’s right to continue with its development, 
 maintenance and/or distribution of CSS’s technology or products. You agree
 that you shall not assert any patent that you own against CSS, its 
 subsidiaries or affiliates, or their customers, direct or indirect, 
 agents and contractors for the manufacture, use, import, licensing, offer
 for sale or sale of any CSS Products.
12. OPEN SOURCE SOFTWARE. Notwithstanding anything to the contrary, you
 are not licensed to (and you agree that you will not) integrate or use 
 this SDK with any Viral Open Source Software or otherwise take any action
 that could require disclosure, distribution, or licensing of all or any 
 part of the SDK in source code form, for the purpose of making derivative
 works, or at no charge. For the purposes of this Section 12, “Viral Open
 Source Software” shall mean software licensed under the GNU General 
 Public License, the GNU Lesser General Public License, or any other 
 license terms that could require, or condition your use, modification, or
 distribution of such software on, the disclosure, distribution, or 
 licensing of any other software in source code form, for the purpose of
 making derivative works, or at no charge. Any violation of the foregoing
 provision shall immediately terminate all of your licenses and other 
 rights to the SDK granted under this Agreement.
13. WAIVER. None of the provisions of this License Agreement shall be 
deemed to have been waived by any act or acquiescence on the part of CSS, 
its agents or employees, but only by an instrument in writing signed by an 
officer of CSS.
14.  INTEGRATION. When conflicting language exists between this License 
Agreement and any other agreement included in the SDK, this License 
Agreement shall supersede. If either you or CSS employ attorneys to enforce
 any rights arising out of or relating to this License Agreement, the 
 prevailing party shall be entitled to recover reasonable attorneys’ fees. 
 You acknowledge that you have read this License Agreement, understand it
 and that it is the complete and exclusive statement of your agreement 
 with CSS that supersedes any prior agreement, oral or written, between 
 CSS and you with respect to the licensing of the SDK. No variation of 
 the terms of this License Agreement will be enforceable against CSS unless
 CSS gives its express consent, in writing signed by an officer of CSS. 
15.  GOVERNMENT LICENSE.  If the SDK is licensed to the U.S. Government
 or any agency thereof, it will be considered to be “commercial computer 
 software” or “commercial computer software documentation,” as those terms 
 are used in 48 CFR § 12.212 or 48 CFR § 227.7202, and is being licensed 
 with only those rights as are granted to all other licensees as set forth 
 in this Agreement.*/
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "logging.h"

#define LOG_HEAD_SIZE 50
#define LOG_LEVEL_SIZE 10

#define ERRORLVL   "[ERROR]  "
#define INFOLVL    "[INFO]   "
#define VERBOSELVL "[VERBOSE]"
#define DEBUGLVL   "[DEBUG]  "
#define TRACELVL   "[TRACE]  "

static bool _trace = false;
static bool _debug = false;
static bool _verbose = false;
static bool _info = false;
static bool _error = true; // default logging level

#define MODULE "logging-"

/******************************************************************************/
/** @fn is_log_verbose
	@brief check the current state of the verbose logging level
	@param none
	@returns true if verbose level is enabled, false otherwise
*/
/******************************************************************************/
bool is_log_verbose( void )
{
	return _verbose;
}

/******************************************************************************/
/** @fn is_log_trace
	@brief check the current state of the trace logging level
	@param none
	@returns true if trace level is enabled, false otherwise
*/
/******************************************************************************/
bool is_log_trace( void )
{
	return _trace;
}

/******************************************************************************/
/** @fn is_log_debug
	@brief check the current state of the debug logging level
	@param none
	@returns true if debug level is enabled, false otherwise
*/
/******************************************************************************/
bool is_log_debug( void )
{
	return _debug;
}

/******************************************************************************/
/** @fn is_log_info
	@brief check the current state of the info logging level
	@param none
	@returns true if info level is enabled, false otherwise
*/
/******************************************************************************/
bool is_log_info( void )
{
	return _info;
}

/******************************************************************************/
/** @fn is_log_error
	@brief check the current state of the error logging level
	@param none
	@returns true if error level is enabled, false otherwise
*/
/******************************************************************************/
bool is_log_error( void )
{
	return _error;
}

/******************************************************************************/
/** @fn is_log_off
	@brief check if logging is off
	@param none
	@returns true if the error level is off, false otherwise
*/
/******************************************************************************/
bool is_log_off( void )
{
	return !_error;
}

/******************************************************************************/
/** @fn get_log_format
	@brief locally defined function to format the log level with date & message
	@param char *buf = place to store the formatted message
	@param const char *msgFormat = message to print
	@param const char *logLevel = the log level of the message
	@returns none
*/
/******************************************************************************/
static inline void get_log_format(char* buf, const char* msgFormat,
								  const char* logLevel)
{
	char timeBuf[LOG_HEAD_SIZE];
	time_t t = time(NULL);
	struct tm* tm = gmtime(&t);
	strftime(timeBuf, LOG_HEAD_SIZE, "%Y-%m-%d %H:%M:%S", tm);

	sprintf(buf, "[%s] - %s - %s\n", timeBuf, logLevel, msgFormat);
}


/******************************************************************************/
/** @fn log_error
	@brief Print a message if the error logging level is enabled
	@returns none
*/
/******************************************************************************/
void log_error(const char* fmt, ...)
{
	if (_error)
	{
		char logFormat[LOG_HEAD_SIZE + strlen(fmt) + LOG_LEVEL_SIZE];
		get_log_format(logFormat, fmt, ERRORLVL);

		va_list args;
		va_start(args, fmt);
		vfprintf(stderr, logFormat, args);
		va_end(args);
	}
}

/******************************************************************************/
/** @fn log_info
	@brief Print a message if the info logging level is enabled
	@returns none
*/
/******************************************************************************/
void log_info(const char* fmt, ...)
{
	if(_info)
	{
		char logFormat[LOG_HEAD_SIZE + strlen(fmt) + LOG_LEVEL_SIZE];
		get_log_format(logFormat, fmt, INFOLVL);

		va_list args;
		va_start(args, fmt);
		vprintf(logFormat, args);
		va_end(args);
	}
}

/******************************************************************************/
/** @fn log_verbose
	@brief Print a message if the verbose logging level is enabled
	@returns none
*/
/******************************************************************************/
void log_verbose(const char* fmt, ...)
{
	if(_verbose)
	{
		char logFormat[LOG_HEAD_SIZE + strlen(fmt) + LOG_LEVEL_SIZE];
		get_log_format(logFormat, fmt, VERBOSELVL);

		va_list args;
		va_start(args, fmt);
		vprintf(logFormat, args);
		va_end(args);
	}
}

/******************************************************************************/
/** @fn log_debug
	@brief Print a message if the debug logging level is enabled
	@returns none
*/
/******************************************************************************/
void log_debug(const char* fmt, ...)
{
	if(_debug)
	{
		char logFormat[LOG_HEAD_SIZE + strlen(fmt) + LOG_LEVEL_SIZE];
		get_log_format(logFormat, fmt, DEBUGLVL);

		va_list args;
		va_start(args, fmt);
		vprintf(logFormat, args);
		va_end(args);
	}
}

/******************************************************************************/
/** @fn log_trace
	@brief Print a message if the trace logging level is enabled
	@returns none
*/
/******************************************************************************/
void log_trace(const char* fmt, ...)
{
	if(_trace)
	{
		char logFormat[LOG_HEAD_SIZE + strlen(fmt) + LOG_LEVEL_SIZE];
		get_log_format(logFormat, fmt, TRACELVL);

		va_list args;
		va_start(args, fmt);
		vprintf(logFormat, args);
		va_end(args);
	}
}

/******************************************************************************/
/** @fn log_me
	@brief local-only function to print a message
	@returns none
*/
/******************************************************************************/
static void log_me( const char* fmt, ... )
{
	char logFormat[LOG_HEAD_SIZE + strlen(fmt) + LOG_LEVEL_SIZE];
	get_log_format(logFormat, fmt, "[LOGGING]");

	va_list args;
	va_start(args, fmt);
	vprintf(logFormat, args);
	va_end(args);
}

/******************************************************************************/
/** @fn log_set_trace
	@brief Turn on the trace & all lower logging levels
	@returns none
*/
/******************************************************************************/
void log_set_trace(bool param)
{
	log_me( "%sSetting logging level to info.", MODULE );
	_trace = param;
	_debug = param;
	_verbose = param;
	_info = param;
	_error = param;
}

/******************************************************************************/
/** @fn log_set_debug
	@brief Turn on the debug & all lower logging levels
	@returns none
*/
/******************************************************************************/
void log_set_debug(bool param)
{
	log_me( "%sSetting logging level to info.", MODULE );
	_trace = !param;
	_debug = param;
	_verbose = param;
	_info = param;
	_error = param;
}

/******************************************************************************/
/** @fn log_set_verbosity
	@brief Turn on the verbose & all lower logging levels
	@returns none
*/
/******************************************************************************/
void log_set_verbosity(bool param)
{
	log_me( "%sSetting logging level to verbose.", MODULE );
	_trace = !param;
	_debug = !param;
	_verbose = param;
	_info = param;
	_error = param;
}

/******************************************************************************/
/** @fn log_set_info
	@brief Turn on the info & all lower logging levels
	@returns none
*/
/******************************************************************************/
void log_set_info(bool param)
{
	log_me( "%sSetting logging level to info.", MODULE );
	_trace = !param;
	_debug = !param;
	_verbose = !param;
	_info = param;
	_error = param;
}

/******************************************************************************/
/** @fn log_set_error
	@brief Turn on the error logging level
	@returns none
*/
/******************************************************************************/
void log_set_error(bool param)
{
	log_me( "%sSetting logging level to error.", MODULE );
	_trace = !param;
	_debug = !param;
	_verbose = !param;
	_info = !param;
	_error = param;
}

/******************************************************************************/
/** @fn log_set_off
	@brief Turn off all further logging
	@returns none
*/
/******************************************************************************/
void log_set_off(bool param)
{
	log_me( "%sTurning off all further logging.", MODULE );
	_trace = !param;
	_debug = !param;
	_verbose = !param;
	_info = !param;
	_error = !param;
}
