# Keyfactor-CAgent
C-Agent for use with Keyfactor Platform

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
	
# Running the agent
There are various logging levels available in the agent:

	./agent -l t is the greatest detail mode and includes traced curl output
	./agent -l d lists all message details other than trace details
	./agent -l v lists all verbose and below messages
	./agent -l i lists all info, warn, and error messages
	./agent -l w lists all warning and error messages
	./agent -l e lists only error messages
	./agent -l o turns off all output messages


