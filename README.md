# C-Agent

![Build Status](https://img.shields.io/badge/build-passing-brightgreen) ![License](https://img.shields.io/badge/license-MIT-blue)

The **C-Agent** is a reference implementation of a Keyfactor Remote Agent designed for IoT-based solutions. It supports the following build modes:

- **OpenSSL**
- **WolfSSL**
- **Raspberry Pi SPI TPM** (Coming Soon)

---

## Table of Contents
1. [Overview](#overview)
2. [OpenSSL Build](#openssl-build)
    - [Install Dependencies](#install-dependencies)
    - [Clone the Repository](#clone-the-repository)
    - [Build the Agent](#build-the-agent)
3. [WolfSSL Build](#wolfssl-build)
    - [Install Dependencies](#install-dependencies-1)
    - [Build WolfSSL](#build-wolfssl)
    - [Build cURL](#build-curl)
    - [Build the Agent](#build-the-agent-1)
4. [TPM Build (Coming Soon)](#tpm-build-coming-soon)
5. [Common Configuration Steps](#common-configuration-steps)
    - [Set Up Directories and Trust Store](#set-up-directories-and-trust-store)
    - [Modify Configuration File](#modify-configuration-file)
    - [Run the Agent](#run-the-agent)
6. [Appendix](#appendix)
    - [Agent Switches](#agent-switches)
    - [Complete Configuration File Data](#complete-configuration-file-data)
7. [Troubleshooting](#troubleshooting)
8. [Contributing](#contributing)
9. [License](#license)

---

## Overview

The Keyfactor C-Agent provides secure communication between IoT devices and the Keyfactor Control Platform. This guide walks you through building and configuring the agent for different modes.

---

## OpenSSL Build

### Install Dependencies

#### Debian-based Distributions (e.g., Ubuntu, Raspbian)
```bash
sudo apt update
sudo apt install -y build-essential git libcurl4-gnutls-dev curl libssl-dev
```

#### RHEL-based Distributions (e.g., RHEL, CentOS)
```bash
sudo dnf update -y
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y curl-devel curl openssl-devel
```

### Clone the Repository
```bash
cd ~
git clone https://github.com/Keyfactor/Keyfactor-CAgent
```

### Build the Agent

#### 64-bit OSes
```bash
cd ~/Keyfactor-CAgent
make clean
make opentest -j$(nproc)
```

#### 32-bit OSes (e.g., Raspberry Pi OS)
```bash
cd ~/Keyfactor-CAgent
make clean
make openpi -j$(nproc)
```

---

## WolfSSL Build

### Install Dependencies

#### Debian-based Distributions
```bash
sudo apt update
sudo apt install -y build-essential git automake autoconf libtool pkg-config wget
```

#### RHEL-based Distributions
```bash
sudo yum update
sudo yum install -y build-essential git automake autoconf libtool pkg-config wget
```

### Build WolfSSL
```bash
cd ~
wget https://github.com/wolfSSL/wolfssl/archive/v5.0.0-stable.tar.gz
tar -xzf v5.0.0-stable.tar.gz
cd wolfssl-5.0.0-stable
./autogen.sh
./configure --enable-tls13 --enable-all
make
sudo make install
sudo ldconfig -v | grep libwolfssl
```

Ensure the output includes:
```
libwolfssl.so.30 -> libwolfssl.so.30.0.0
```

### Build cURL with WolfSSL
```bash
cd ~
wget https://github.com/curl/curl/archive/refs/tags/curl-7_81_0.tar.gz
tar -xvf curl-7_81_0.tar.gz
cd curl-curl-7_81_0/
autoreconf -fi
./configure --with-wolfssl
make -j$(nproc)
sudo make install
sudo ldconfig
```

### Build the Agent

#### 64-bit OSes
```bash
cd ~/Keyfactor-CAgent
make clean
make wolftest -j$(nproc)
```

#### 32-bit OSes
```bash
cd ~/Keyfactor-CAgent
make clean
make wolftest -j$(nproc)
```

---

## TPM Build (Coming Soon)

This feature is under development. Stay tuned for updates.

---

## Common Configuration Steps

### Set Up Directories and Trust Store
```bash
sudo mkdir --parents /home/keyfactor/Keyfactor-CAgent/certs/
sudo chown $(whoami):$(whoami) /home/keyfactor/Keyfactor-CAgent/certs
nano /home/keyfactor/Keyfactor-CAgent/certs/trust.store
```
Copy the PEM-formatted certificate into the `trust.store` file.

### Modify Configuration File
```bash
cd ~/Keyfactor-CAgent
nano config.json
```
Update the configuration file with your instance details.

### Run the Agent
```bash
cd ~/Keyfactor-CAgent
./agent -l t
```

---

## Appendix

### Agent Switches
[List all switches here with examples.]

### Complete Configuration File Data
[Include detailed explanations of configuration fields.]

---

## Troubleshooting

- **Dependency Installation Errors**: Ensure your system package manager is updated.
- **Build Errors**: Verify all dependencies are installed and compatible.
- **Runtime Issues**: Check logs with `-l t` for detailed output.

---

## Contributing

Contributions are welcome! Submit issues or pull requests on [GitHub](https://github.com/Keyfactor/Keyfactor-CAgent).

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
