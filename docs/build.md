# Build

All build targets are defined in the repository-root [`makefile`](../makefile).
The makefile compiles with `gcc -std=gnu99`, treats warnings as errors
(`-Werror`), and emits a binary named `agent` (or a shared library
`libagent.so` for the library targets).

The selection of crypto backend and target-specific behavior is done
entirely through compile-time `-D` flags set by the makefile target:

| Flag                | Effect                                          |
|---------------------|-------------------------------------------------|
| `__OPEN_SSL__`      | Build against OpenSSL (`openssl_wrapper/`).     |
| `__WOLF_SSL__`      | Build against wolfSSL (`wolfssl_wrapper/`).     |
| `__TPM__`           | Load a `tpm2tss` OpenSSL engine for key ops.    |
| `__MAKE_LIBRARY__`  | Build shared library, renames `main` → `KF_main`. |
| `__RUN_CHAIN_JOBS__`| Run chained follow-on jobs (set by default).    |
| `_POSIX_C_SOURCE=200809L` | POSIX.1-2008 (set by default).             |

## Build matrix

| Target         | Flags                             | Output        | When to use                               |
|----------------|-----------------------------------|---------------|-------------------------------------------|
| `opentest`     | `__OPEN_SSL__`                    | `agent`       | 64-bit Linux host, OpenSSL.               |
| `openpi`       | `__OPEN_SSL__`, `-Wno-format`     | `agent`       | 32-bit Linux host (e.g. Raspberry Pi OS). |
| `wolftest`     | `__WOLF_SSL__`                    | `agent`       | 64-bit Linux host, wolfSSL.               |
| `wolfpi`       | `__WOLF_SSL__`, `-Wno-format`     | `agent`       | 32-bit Linux host, wolfSSL.               |
| `openlib`      | `__OPEN_SSL__`, `__MAKE_LIBRARY__`| `libagent.so` | Shared library, OpenSSL backend.          |
| `wolflib`      | `__WOLF_SSL__`, `__MAKE_LIBRARY__`| `libagent.so` | Shared library, wolfSSL backend.          |
| `openinstall`  | *(consumes `libagent.so`)*        | —             | `sudo cp libagent.so /usr/lib` + chmod.   |
| `wolfinstall`  | *(consumes `libagent.so`)*        | —             | Same as above.                            |
| `rpi9670test`  | `__OPEN_SSL__`, `__TPM__`         | `agent`       | Raspberry Pi with a TPM via tpm2tss.      |

Always run `make clean` before switching targets — the targets share
object-file paths and stale objects from a different backend will cause
link errors.

## OpenSSL builds

Install dependencies (see [`installation.md`](installation.md)), then:

```bash
# 64-bit host
cd ~/Keyfactor-CAgent
make clean
make opentest -j$(nproc)

# 32-bit host (Raspberry Pi OS, etc.)
make clean
make openpi -j$(nproc)
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

The `makefile`'s `WOLFLIBS` variable expects wolfSSL headers under
`/usr/local/include/wolfssl` and cURL headers under
`/usr/local/include/curl`, with libraries under `/usr/local/lib` — the
commands above are wired to land there.

### Build the agent

```bash
cd ~/Keyfactor-CAgent
make clean
make wolftest -j$(nproc)   # 64-bit
# or
make wolfpi   -j$(nproc)   # 32-bit
```

The list of wolfSSL symbols the agent relies on is tracked in
[`wolfssl_wrapper/wolfssl_functions_used.txt`](../wolfssl_wrapper/wolfssl_functions_used.txt)
— useful if you are porting to a cut-down wolfSSL build.

## Shared-library builds

The `openlib` and `wolflib` targets build `libagent.so` and rename
`main()` to `KF_main()` via the `__MAKE_LIBRARY__` guard in
[`agent.c`](../agent.c):

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
make openlib -j$(nproc)   # or wolflib
sudo make openinstall     # or wolfinstall
```

The install targets copy `libagent.so` to `/usr/lib` and set `755`
permissions.

> **Note.** There is no in-tree example program that links against
> `libagent.so` and invokes `KF_main`. Treat this target as a packaging
> option, not a documented embedding API.

## TPM build (Raspberry Pi, tpm2tss)

The `rpi9670test` target builds an OpenSSL-backed agent that loads a
`tpm2tss` OpenSSL engine to use a TPM-resident private key. The engine
name is passed with `-e` at runtime — see [`cli.md`](cli.md).

Prerequisites beyond the OpenSSL ones:

- `tpm2-tss` (TPM Software Stack)
- `tpm2-tss-engine` — the OpenSSL engine that exposes TPM keys
- The engine `.so` must live under a path the linker can find. The
  makefile currently searches:
  - `/usr/lib/arm-linux-gnueabihf/engines-1.1/`
  - `/usr/lib/arm-linux-gnueabihf/engines-3/` (for Raspberry Pi)
  - `/usr/lib/x86_64-linux-gnu/engines-1.1/` (for x86_64 Linux)

Build:

```bash
make clean
make rpi9670test -j$(nproc)
```

Runtime:

```bash
./agent -e tpm2tss -l i
```

The `-e` switch selects the engine name; if omitted the agent falls
back to `"dynamic"` (set in `parse_parameters()` in `agent.c`).

## Cleaning

```bash
make clean        # removes all .o files under the repo and the agent binary
make cleanall     # alias for clean
```

Both targets delete every `*.o` matching the OpenSSL or wolfSSL object
lists plus the `agent` executable.
