//** @file RPI_GPIO.c */
/************************************************************/
//** @detail Allow access to the GPIO pins using sys/stat.h */
//** that way we don't have to worry about having wiringPi  */
//** or other items getting in the way                      */
/************************************************************/

#include "rpi_gpio.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "global.h"
#include "logging.h"

/******************************************************************************/
/*									GLOBAL DEFINES												   */
/******************************************************************************/
#define LOW	 		"0"
#define HI			"1"
#define LEDPIN		"16"	// Use GPIO 16 = P1-36, P1-39 is a close ground pin

#define MODULE "RPI_GPIO-"

/******************************************************************************/
/*									LOCAL VARIABLES												   */
/******************************************************************************/

/******************************************************************************/
/*									LOCAL FUNCTION PROTOTYPES									   */
/******************************************************************************/
static int write_gpio_file(const char *file, const char *stuff);


/******************************************************************************/
/*									LOCAL FUNCTION DEFINITIONS									   */
/******************************************************************************/
/******************************************************************************/
/** @fn write_gpio_file
	@brief write a file to the gpio
	@retval 1 on success,
	@retval 0 on failure
*/
/******************************************************************************/
static int write_gpio_file(const char *file, const char *stuff)
{
	#undef FUNCTION
	#define FUNCTION "write_gpio_file"
	int stuffLen;

	// open the GPIO
	int fd = open( file, O_WRONLY );
	if ( -1 == fd )
	{
		log_error("%s%s-Error opening gpio as file", MODULE, FUNCTION);
		goto err;
	}

	// try to write the data out to the GPIO
	stuffLen = strlen(stuff);
	if ( stuffLen != write( fd, stuff, stuffLen) )
	{
		log_error("%s%s-Failed to write %s to %s!", MODULE, FUNCTION, stuff, file );
		goto err;
	}

	close ( fd );
	return 1; // success!

err:
	close ( fd );
	return 0;
} // write_gpio_file


/******************************************************************************/
/*									GLOBAL FUNCTION DEFINITIONS									   */
/******************************************************************************/
/******************************************************************************/
/** @fn setup_io
	@brief setup the GPIO using /sys/class/gpio file writes
	@retval 1 on success,
	@retval 0 on failure
*/
/******************************************************************************/
int setup_io( void )
{
	#undef FUNCTION
	#define FUNCTION "setup_io"

#ifdef __RPI__
	int pi = 1;
#else
	int pi = 0;
#endif

	int res;

	if ( !pi )
	{
		log_error("%s%s-__RPI__ is not defined in global.h", MODULE, FUNCTION);
		goto err;
	}

	char buffer[33];
	sprintf( buffer, "/sys/class/gpio/gpio%s/direction", LEDPIN );
	if ( -1 == access( buffer, F_OK ) )  // the pin isn't exported yet
	{
		res = write_gpio_file("/sys/class/gpio/export", LEDPIN);
		if ( 0 > res )
		{
			goto err;
		}

		// now wait for the os to generate a symbolic link to the gpio pin
		struct stat bufferStatus;
		int pinExported = -1;
		do
		{
			sleep(1);
			pinExported = stat( buffer, &bufferStatus );
		} while ( pinExported != 0 );
	}

	// Set the pin to be an output pin
	res = write_gpio_file( buffer, "out" );
	if ( 0 > res )
	{
		goto err;
	}

	turn_off_led(); // turn off the gpio pin
	return 1; // success!

err:
	return 0;
} // setup_io

/******************************************************************************/
/** @fn turn_on_led
	@brief Turn on the GPIO pin
	@returns none
*/
/******************************************************************************/
void turn_on_led( void )
{
	#undef FUNCTION
	#define FUNCTION "turn_on_led"
	log_verbose("%s%s-Turning on LED", MODULE, FUNCTION);
	char buffer[29];
	sprintf(buffer, "/sys/class/gpio/gpio%s/value", LEDPIN);
	write_gpio_file( buffer, HI );
	return;
} // turn_on_led

/******************************************************************************/
/** @fn turn_off_led
	@brief Turn off the LED
	@returns none
*/
/******************************************************************************/
void turn_off_led( void )
{
	#undef FUNCTION
	#define FUNCTION "turn_off_led"
	log_verbose("%s%s-Turning off LED", MODULE, FUNCTION);
	char buffer[29];
	sprintf(buffer, "/sys/class/gpio/gpio%s/value", LEDPIN);
	write_gpio_file( buffer, LOW );
	return;
}

/******************************************************************************/
/** @fn cleanup_io
	@brief Free the IO pins we have exported
	@returns none
*/
/******************************************************************************/
void cleanup_io( void )
{
	#undef FUNCTION
	#define FUNCTION "cleanup_io"
	log_verbose("%s%s-Unexporting I/O for LED", MODULE, FUNCTION);
	char buffer[29];
	sprintf(buffer, "/sys/class/gpio/unexport");
	write_gpio_file( buffer, LEDPIN );
	return;
}

/******************************************************************************/
/*											END OF FILE											   */
/******************************************************************************/
