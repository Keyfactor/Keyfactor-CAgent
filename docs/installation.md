# Installation

This page covers host prerequisites and getting the source onto the
machine. For the actual build commands see [`build.md`](build.md).

The agent is tested on Linux. The minimum toolchain is a C99-capable
GCC — the `makefile` invokes `gcc -std=gnu99`.

## Host prerequisites

The agent always needs:

- `gcc` with C99 support and `make` (Development Tools)
- `git`
- `libcurl` development headers

One of the following SSL stacks is required, matching the build
configuration you intend to use (see [`build.md`](build.md) for the
full variable reference):

- **OpenSSL build** (`CRYPTO=openssl`, any `OUT`, optionally `pi=1`) —
  distro `libssl` / `openssl-devel` headers.
- **wolfSSL build** (`CRYPTO=wolfssl`, any `OUT`, optionally `pi=1`) —
  wolfSSL built from source **and** `libcurl` rebuilt against it (stock
  distro `libcurl` is linked against OpenSSL and will not work).
- **TPM build** (`CRYPTO=openssl tpm=1`, typically also `pi=1`) —
  OpenSSL plus `tpm2-tss` and the `tpm2-tss-engine` OpenSSL engine,
  installed at an engines path the linker can find (see the TPM section
  of [`build.md`](build.md) for the searched paths).

## Debian / Ubuntu / Raspberry Pi OS

```bash
sudo apt update
sudo apt install -y build-essential git curl
# OpenSSL build:
sudo apt install -y libcurl4-gnutls-dev libssl-dev
# wolfSSL build — extra tooling required to build wolfSSL and cURL from source:
sudo apt install -y automake autoconf libtool pkg-config wget
```

On 32-bit Raspberry Pi OS add `pi=1` to the `make` invocation — it adds
`-Wno-format` to suppress spurious warnings from printing 64-bit values
with `%lu`.

## RHEL / CentOS / Rocky

```bash
sudo dnf update
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y git curl
# OpenSSL build:
sudo dnf install -y curl-devel openssl-devel
# wolfSSL build — extra tooling required to build wolfSSL and cURL from source:
sudo dnf install -y automake autoconf libtool pkg-config wget
```

## Clone the repository

```bash
cd ~
git clone https://github.com/keyfactor-iot/Keyfactor-CAgent
cd Keyfactor-CAgent
```

## Next steps

- Build the agent for your target — see [`build.md`](build.md).
- Prepare the `config.json` and trust store — see
  [`configuration.md`](configuration.md).
- Review the enrollment flow before first run — see
  [`enrollment-and-certificates.md`](enrollment-and-certificates.md).
