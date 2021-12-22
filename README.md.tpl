# {{ name }}
## {{ integration_type | capitalize }}

{{ description }}

# C-Agent Build Dependencies:
Before building the agent, install the following dependencies:

	build-essential
	git
	libcurl4-gnutls-dev
	curl

When building for openSSL, also install this dependency:

	libssl-dev

When building the wolfSSL version, also install these dependencies:

	automake
	autoconf
	libtool

For example, if you are on a Debian based build (Debian/Ubuntu/Xubuntu/Raspbian/...) you execute the following commands to install all of the above dependencies.
	
	sudo apt update
	sudo apt install -y build-essential git libcurl4-gnutls-dev curl libssl-dev automake autoconf libtool
	sudo apt autoremove -y
	
For RHEL based systems (rhel/centos/rocky...) the following commands should install the required dependencies.
        
	sudo yum update
	sudo yum install -y curl-devel openssl-devel

# OpenSSL version requirements
When running an openSSL release, version 1.1.1 or later is recommended.  
The agent runs on openSSL 1.0.1.  To determine the openssl version installed on a Linux build, run the following command:

	openssl version

# wolfSSL build and install
Make sure the Wolf dependencies are loaded.  Then clone the latest wolfSSL version (minimum v4.4.0), configure and build the version as follows:

	cd ~
	git clone https://github.com/wolfssl/wolfssl.git
	cd wolfssl
	./autogen.sh
	./configure --enable-all
	make -j$(nproc)
	sudo make install
	sudo ldconfig -v | grep libwolfssl

Make sure the last command has a line that reads out something similar to:

	libwolfssl.so.24 -> libwolfssl.so.24.2.0

That tells you that the library is installed correctly.

# Making the Agent
It is possible to build both the openSSL and the wolfSSL version of the agent by using different make switches, see below.

	cd ~
	git clone https://github.com/Keyfactor/Keyfactor-CAgent.git
	cd ~/Keyfactor-CAgent
	make clean <----- do this to clean all objects and rebuild all

Only build one version of the agent, either openSSL or wolfSSL:

	make opentest -j$(nproc) <-------- The openssl build 
	make wolftest -j$(nproc) <-------- The wolfssl build 
	make tpm -j$(nproc) <------------- For use with the SLB9670 & Raspberry Pi
	
# Running the agent

	./agent -l <switch_see_below>  enables logging (default is info)
	./agent -l t is the greatest detail mode and includes traced curl output
	./agent -l d lists all message details other than trace details
	./agent -l v lists all verbose and below messages
	./agent -l i lists all info, warn, and error messages
	./agent -l w lists all warning and error messages
	./agent -l e lists only error messages
	./agent -l o turns off all output messages

	./agent -c <path_and_filename> overrides the default configuration file

	./agent -h overrides the agent name with $HOSTNAME_$DATETIME

	./agent -e <engine> the crypto engine to use (e.g., tpm2tss) NOTE:
		 				must compile the TPM version of the agent

# Agent History
	version 2.8.5
		Modified logging to use heap.  
		Logging now can use a large file (e.g. 5MBytes) that will roll over when it hits the max file size.
		The system will interact with the 5MByte file in smaller chunks (e.g., 256kBytes) of heap memory.
	version 2.8.4
		Fixed issue where a re-registered agent did not have AgentId updated
	version 2.8.3
		Additional memory leaks found and squashed
	version 2.8.2
		Fixed some memory leaks
	version 2.8.1
		Fixed logging to file bug
	version 2.8.0
		Added support for bootstrap certificates (defined in config.json)
		Updated Licensing information
	version 2.7.2
		Fixed a bug where CodeString isn't sent by platform, but HResult is
	version 2.7.1
		Fixed bug with agent cert expiry
	version 2.7.0
		Added -h switch.  Use this to have the AgentName = hostname_datetime
		Added second hit to /Session/Register with client parameters used by the Registration Handler to configure re-enrollment jobs on the certificate stores.
	version 2.6.1
		Added -c switch to allow configuration file location to be passed to the agent
	version 2.6.0
		Updated agent for v8.5.2 of the Keyfactor Platform
	version 2.5.2
		Fixed bugs in openSSL layer when performing management jobs
	version 2.5.1 
		Fixed a bug in the openSSL wrapper cleanup causing segfaults
		Added a check to the inventory and management jobs to validate cert store exists
		Added sanity checks on the initital configuration file
		Added ECC 192 key generation
		Set default logging level to INFO
	version 2.5.0
		Log to file upon agent shutting down
		Agent runs through all jobs once, this allows cron to schedule it
		Added warning log level
		Added a priority queue for agent jobs upon initial retrieval
		Ignore chained jobs - all inventory jobs run immediate
		Check if a store is a directory before reading/writing
		Check if re-enrollment, inventory, or managment jobs are targeting the agent store & don't run them
		Added agent cert re-enrollment upon platform requesting it
	version 2.1.0
		Added TPM for raspberry pi with Infineon SLB9670 and openSSL
	version 2.0.0
		Created wrapper classes to separate Keyfactor Platform from ssl/crypto implementation
