# C-Agent
The C-Agent is a reference implementation of a Keyfactor Remote Agent geared toward use in IoT based solutions.
The Keyfactor-CAgent can be built for three (3) different modes:
- openSSL
- wolfSSL
- Raspberry Pi SPI TPM (e.g., SLB9760 or STPM4RasPI)

#
#
# OpenSSL build
#

## Install the __dependencies__ depending on your Linux distribution:

#### Debian based (e.g., Poky, Ubuntu, Raspian, Raspberry Pi OS, etc.)
	sudo apt update
	sudo apt install -y build-essential git libcurl4-gnutls-dev curl libssl-dev

#### RHEL based (RHEL, CentOS, Rocky, etc.)
	sudo yum update
	sudo yum install -y build-essential git curl-devel curl openssl-devel

## Clone the git repository
	cd ~
	git clone https://github.com/Keyfactor/Keyfactor-CAgent

## Build the agent against the OpenSSL target
	cd ~/Keyfactor-CAgent
	make clean
	make opentest -j$(nproc)

## Configure and run the Agent (see below)

#
#
# WolfSSL build
#

## Install the __dependencies__ depending on your Linux distribution:

#### Debian based (e.g., Poky, Ubuntu, Raspian, Raspberry Pi OS, etc.)
	sudo apt update
	sudo apt install -y build-essential git automake autoconf libtool pkg-config wget

#### RHEL based (RHEL, CentOS, Rocky, etc.)
	sudo yum update
	sudo yum install -y build-essential git automake autoconf libtool pkg-config wget

## Download, build, and install wolfSSL
#### Make sure the Wolf dependencies are loaded.  Then clone the latest wolfSSL version (minimum v4.4.0), configure and build the version as follows:
	cd ~
	wget https://github.com/wolfSSL/wolfssl/archive/v5.0.0-stable.tar.gz
	tar -xzf v5.0.0-stable.tar.gz
	cd wolfssl-5.0.0-stable
	./autogen.sh
	./configure --enable-tls13 --enable-all
	make
	sudo make install
	sudo ldconfig -v | grep libwolfssl

#### Make sure the last command has a line that reads out something similar to:
	libwolfssl.so.30 -> libwolfssl.so.30.0.0
#### That tells you that the library is installed correctly.

## Download, build, and install cURL for use with wolfSSL
	cd ~
	wget https://github.com/curl/curl/archive/refs/tags/curl-7_81_0.tar.gz
	tar -xvf curl-7_81_0.tar.gz
	cd ~/
    cd curl-curl-7_81_0/
	autoreconf -fi
	./configure --enable-warnings --enable-werror --enable-headers-api --with-wolfssl --enable-debug
	make -j$(nproc)
	sudo make install
	sudo ldconfig

## Clone the Keyfactor-CAgent git repository
	cd ~
	git clone https://github.com/Keyfactor/Keyfactor-CAgent

## Build the agent against the WolfSSL target
	cd ~/Keyfactor-CAgent
	make clean
	make wolftest -j$(nproc)

## Configure and Run the Agent (see below)

#
#
# Raspberry Pi + openSSL + TPM Build (Coming soon)
#
Coming soon
#
#
# AREA COMMON TO ALL BUILDS 
#

# Configure the agent

### Create required directories, files, and update ownership
	sudo mkdir --parents /home/keyfactor/Keyfactor-CAgent/certs/
	sudo chown $(whoami):$(whoami) /home/keyfactor/Keyfactor-CAgent/certs

### Add your Keyfactor Test Instance's Root Certificate to the trust.store
#### First get your Test Instance's Root Certificate by navigating to the Marketplace instance web site & downloading the certificate as a PEM file. 
	nano /home/keyfactor/Keyfactor-CAgent/certs/trust.store
#### Open the PEM file in a text editor and copy into the trust.store file

### Modify the agent configuration file
	cd ~/Keyfactor-CAgent
	nano config.json
#### Add these data lines into the file, replacing the Hostname, Username, and Password entries with the relevant data from your Marketplace instance.  
#### Also replace the Agent name and CSR Subject with a unique name to your Marketplace instance.
#### Also note this file is case senstivive!
	{
		"AgentId": "",
		"AgentName": "UniqueName",
		"Hostname": "www.yourtestdrive.com",
		"Username": "testdrive\\yourusername",
		"Password": "yourpassword",
		"VirtualDirectory": "KeyfactorAgents",
		"TrustStore": "/home/keyfactor/Keyfactor-CAgent/certs/trust.store",
		"AgentCert": "/home/keyfactor/Keyfactor-CAgent/certs/Agent-cert.pem",
		"AgentKey": "/home/keyfactor/Keyfactor-CAgent/certs/Agent-key.pem",
		"CSRKeyType": "ECC",
		"CSRKeySize": 256,
		"CSRSubject": "CN=UniqueName",
		"EnrollOnStartup": true,
		"UseSsl": true,
		"LogFile": "agent.log"
	}

#### The Agent uses a config.json file to provide inputs into the system.
#### For this reference example, we use unencrypted passwords, usernames, and the like.
#### In a full implementation, this data is either secured in trusted element space and/or encrypted and stored as a blob.
#### To allow easier exploration, this is not done here & is implemented depending on physical hardware and business requirements.

# Run the Agent
	cd ~/Keyfactor-CAgent
	./agent -l t

#
# APPENDIX A: Agent switches

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

# APPENDIX B: Complete Configuration file data
__AgentID__ : Assigned by Keyfactor Control.  Please leave blank.

__AgentName__ : <optional> Leave blank if using the `-h` argument with the agent. This is <required> if not using the `-h` switch.

__ClientParameterPath__ :  <optional> Used to pass optional client parameters to the Registration session.

__Hostname__ : <required> Either the IP address or the FQDN of the Keyfactor Control Web Address

__Password__ : <optional> If using basic authentication to the Keyfactor Control Platform, then the password for the user.  This can also be omitted if a reverse proxy is injecting authentication credentials into the HTTP header.

__Username__ : <optional> If using basic authentication to the Keyfactor Control Platform, then the domain and username to log into the Keyfactor Control Platform (remember, the \ character must be escaped -- e.g., KEYFACTOR\\Administrator).  This can also be omitted if a reverse proxy is injecting authentication credentials into the HTTP header.

__VirtualDirectory__ : <required> Set this to KeyfactorAgents if you are not using a reverse proxy.  If you are using a reverse-proxy, set it to the virtual directory that is mapped to KeyfactorAgents.

__TrustStore__ : <required> The location of additional certificates that are trusted by the Agent.  This list is appended to the standard CA certificate store located in `/etc/ssl/certs/ca-certificates.crt` for Ubuntu.

__AgentCert__ : <required> The (eventual) location of the Agent's certificate.  This is the certificate used by the Agent to call into the platform.

__AgentKey__ : <required> The (eventual) location of the Agent's private key.  This is the key used by the Agent to call into the platform.

__AgentKeyPassword__ : <optional> An optional passphrase for decoding the Agent Key.  Note, if a TPM, Secure Element, or secure area is used, this **must be defined**.

__CSRKeyType__ : <required> The Key type for the AgentKey (ECC or RSA).  This must match the template defined in the Keyfactor Platform.

__CSRKeySize__ : <required> The Key size for the AgentKey.  This must be equal to or greater than the minimum size defined in the template.

__CSRSubject__ : <optional> If the `-h` command line switch is used, this field is not used.  This field is <required> if the command line switch is not used.

__EnrollOnStartup__ : <required> true = The agent will register itself with the platform.   The agent will set this to false once the agent has registered and been approved.

__UseBootstrapCert__ : <optional> true = Use a bootstrap certificate when registering with the platform.  false = otherwise.

__BootstrapCert__ : <optional/required> If UseBootstrapCert is true, this is required & is the path/filename for the certificate.

__BootstrapKey__ : <optional/required> If UseBootstrapCert is false, this is required & is the path/filename of the private key for the bootstrap certificate.

__BootstrapKeyPassword__ : <optional> An optional passphrase used to decode the bootstrap key.

__UseSsl__ : <required> true = https:// is used.  false = http:// is used. Both refer to the Keyfactor Control Platform communications.  Really, this should always be true in a production environment.

__Serialize__ : <optional> true = use a shared network file to grab a serial number/name combination for the AgentName and CN.  false = otherwise.Typically this is an nfs file store that is on the production line.  Most IoT implementations do not use this method, as UKIDs and names are defined by the host and UKID chips (e.g., [1-wire EEPROM with 64-bit UKID](https://www.microchip.com/wwwproducts/en/AT21CS01) )

__SerialFile__ : <optional> The location of a mounted nfs file store & file to use in the serialization operation.

__LogFile__ : <required> The path/filename of a log file for the agent.  **NOTE:** This log file uses the same logging level as the agent.  (See command line arguments for the agent)

__httpRetries__ : <required> The number of times the agent will attempt to connect to the Keyfactor Control platform before recording an error.  Minimum value is 1.

__retryInterval__ : <required> The time delay (in seconds) between httpRetries.

__LogFileIndex__ : <AgentUseOnly> This is used as an index into the LogFile to allow for a rolling maximum sized log file. 

#### __WARNING:__ if the Agent's LogFile is deleted, this **has** to be set to zero (0).
