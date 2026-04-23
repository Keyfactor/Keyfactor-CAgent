# Build

All build configuration lives in the repository-root [`makefile`](../makefile).
The makefile compiles with `gcc -std=gnu99`, treats warnings as errors
(`-Werror`), and emits a binary named `agent` (or a shared library
`libagent.so` when building a library).

Builds are configured by setting variables on the `make` command line
rather than by picking from a long list of target names. The makefile
composes the right compile/link flags from a small number of axes:

## Build variables

| Variable | Values               | Default   | Effect                                              |
|----------|----------------------|-----------|-----------------------------------------------------|
| `CRYPTO` | `openssl`, `wolfssl` | `wolfssl` | Selects the crypto backend and its wrapper.         |
| `OUT`    | `exec`, `lib`        | `exec`    | Build the `agent` executable or `libagent.so`.      |
| `qa`     | any non-empty value  | *(unset)* | Adds `-D__QATESTING__` (enables QA hooks).          |
| `pi`     | any non-empty value  | *(unset)* | Adds `-Wno-format` (32-bit Pi targets).             |
| `tpm`    | any non-empty value  | *(unset)* | Adds `-D__TPM__` and links `-ltpm2tss`.             |

Derived `-D` defines set by the makefile:

| Flag                      | Set by                  |
|---------------------------|-------------------------|
| `__OPEN_SSL__`            | `CRYPTO=openssl`        |
| `__WOLF_SSL__`            | `CRYPTO=wolfssl`        |
| `__MAKE_LIBRARY__`        | `OUT=lib`               |
| `__QATESTING__`           | `qa=1`                  |
| `__TPM__`                 | `tpm=1`                 |
| `__RUN_CHAIN_JOBS__`      | always (default on)     |
| `_POSIX_C_SOURCE=200809L` | always (default on)     |
| `_XOPEN_SOURCE=600`       | `CRYPTO=wolfssl` only   |

Object files land in per-configuration directories under
`build/$(CRYPTO)-$(OUT)/`, so switching between backends no longer
requires a `make clean` in between.

## Common combinations

| Goal                                  | Command                                         |
|---------------------------------------|-------------------------------------------------|
| 64-bit Linux, OpenSSL                 | `make CRYPTO=openssl OUT=exec`                  |
| 32-bit Linux / Raspberry Pi, OpenSSL  | `make CRYPTO=openssl OUT=exec pi=1`             |
| 64-bit Linux, wolfSSL                 | `make CRYPTO=wolfssl OUT=exec`                  |
| 32-bit Linux / Raspberry Pi, wolfSSL  | `make CRYPTO=wolfssl OUT=exec pi=1`             |
| Shared library, OpenSSL               | `make CRYPTO=openssl OUT=lib`                   |
| Shared library, wolfSSL               | `make CRYPTO=wolfssl OUT=lib`                   |
| QA build, OpenSSL                     | `make CRYPTO=openssl OUT=exec qa=1`             |
| QA build, wolfSSL                     | `make CRYPTO=wolfssl OUT=exec qa=1`             |
| Raspberry Pi + TPM (tpm2tss, OpenSSL) | `make CRYPTO=openssl OUT=exec pi=1 tpm=1`       |
| Install shared library (OpenSSL)      | `make CRYPTO=openssl OUT=lib install`           |
| Install shared library (wolfSSL)      | `make CRYPTO=wolfssl OUT=lib install`           |

## OpenSSL builds

Install dependencies (see [`installation.md`](installation.md)), then:

```bash
cd ~/Keyfactor-CAgent
make clean

# 64-bit host
make CRYPTO=openssl OUT=exec -j$(nproc)

# 32-bit host (Raspberry Pi OS, etc.)
make CRYPTO=openssl OUT=exec pi=1 -j$(nproc)
```

The resulting `./agent` expects a `config.json` next to it unless `-c`
is supplied. See [`configuration.md`](configuration.md).

## wolfSSL builds

wolfSSL is **not** available from most distro package managers in a
form this project links against, and system `libcurl` is linked against
OpenSSL. Both must be built from source and installed before the agent.

### Build wolfSSL

```bash
cd ~
wget https://github.com/wolfSSL/wolfssl/archive/v5.0.0-stable.tar.gz
tar -xzf v5.0.0-stable.tar.gz
cd wolfssl-5.0.0-stable
./autogen.sh
./configure --enable-tls13 --enable-all
make
sudo make install
sudo ldconfig
ldconfig -v 2>/dev/null | grep libwolfssl
```

Confirm the loader reports something like
`libwolfssl.so.30 -> libwolfssl.so.30.0.0`.

### Build cURL against wolfSSL

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

The makefile expects wolfSSL headers under `/usr/local/include/wolfssl`
and cURL headers under `/usr/local/include/curl`, with libraries under
`/usr/local/lib` — the commands above are wired to land there.

### Build the agent

```bash
cd ~/Keyfactor-CAgent
make clean

# 64-bit
make CRYPTO=wolfssl OUT=exec -j$(nproc)

# 32-bit
make CRYPTO=wolfssl OUT=exec pi=1 -j$(nproc)
```

The list of wolfSSL symbols the agent relies on is tracked in
[`wolfssl_wrapper/wolfssl_functions_used.txt`](../wolfssl_wrapper/wolfssl_functions_used.txt)
— useful if you are porting to a cut-down wolfSSL build.

## Shared-library builds

`OUT=lib` builds `libagent.so` and renames `main()` to `KF_main()` via
the `__MAKE_LIBRARY__` guard in [`agent.c`](../agent.c):

```c
#ifdef __MAKE_LIBRARY__
int KF_main(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
```

`KF_main` has the same signature and semantics as `main` — callers
supply `argv`-style arguments, the function runs one session, and
returns `EXIT_SUCCESS` or `EXIT_FAILURE`.

Build and install:

```bash
make clean

# Build the .so
make CRYPTO=openssl OUT=lib -j$(nproc)   # or CRYPTO=wolfssl

# Install to /usr/lib (requires sudo)
make CRYPTO=openssl OUT=lib install      # or CRYPTO=wolfssl
```

The `install` target copies `libagent.so` to `/usr/lib` with mode
`0755`. Invoking `install` when `OUT=exec` is an error — the target
only makes sense for library builds.

> **Note.** There is no in-tree example program that links against
> `libagent.so` and invokes `KF_main`. Treat this target as a packaging
> option, not a documented embedding API.

## TPM build (Raspberry Pi, tpm2tss)

Setting `tpm=1` produces an agent that loads a `tpm2tss` OpenSSL
engine to use a TPM-resident private key. The engine name is passed
with `-e` at runtime — see [`cli.md`](cli.md).

Prerequisites beyond the OpenSSL ones:

- `tpm2-tss` (TPM Software Stack)
- `tpm2-tss-engine` — the OpenSSL engine that exposes TPM keys
- The engine `.so` must live under a path the linker can find. The
  makefile searches, depending on `pi`:
  - `pi=1`: `/usr/lib/arm-linux-gnueabihf/engines-1.1/` and
    `/usr/lib/arm-linux-gnueabihf/engines-3/`
  - otherwise: `/usr/lib/x86_64-linux-gnu/engines-1.1/`

Build:

```bash
make clean
make CRYPTO=openssl OUT=exec pi=1 tpm=1 -j$(nproc)
```

Runtime:

```bash
./agent -e tpm2tss -l i
```

The `-e` switch selects the engine name; if omitted the agent falls
back to `"dynamic"` (set in `parse_parameters()` in `agent.c`).

## Cleaning

```bash
make clean
```

Removes the `build/` directory (all per-configuration object trees)
along with the `agent` binary and any `libagent.so` at the repo root.
`cleanall` and `deleteallobs` are aliases for `clean`.

## Legacy target names

The following single-word targets are retained as thin aliases that
forward to the variable-driven form — they exist for muscle memory and
CI scripts that predate the current makefile. New work should prefer
the explicit `CRYPTO=… OUT=…` form above.

| Legacy target   | Equivalent to                                    |
|-----------------|--------------------------------------------------|
| `wolftest`      | `make CRYPTO=wolfssl OUT=exec`                   |
| `wolflib`       | `make CRYPTO=wolfssl OUT=lib`                    |
| `wolfpi`        | `make CRYPTO=wolfssl OUT=exec pi=1`              |
| `wolfinstall`   | `make CRYPTO=wolfssl OUT=lib install`            |
| `opentest`      | `make CRYPTO=openssl OUT=exec`                   |
| `openlib`       | `make CRYPTO=openssl OUT=lib`                    |
| `openpi`        | `make CRYPTO=openssl OUT=exec pi=1`              |
| `openinstall`   | `make CRYPTO=openssl OUT=lib install`            |
| `qatesting`     | `make CRYPTO=openssl OUT=exec qa=1`              |
| `qawolftesting` | `make CRYPTO=wolfssl OUT=exec qa=1`              |
| `rpi9670test`   | `make CRYPTO=openssl OUT=exec pi=1 tpm=1`        |
