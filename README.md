# Keyfactor C-Agent

![License](https://img.shields.io/badge/license-Apache%202.0-blue)

A reference implementation of a Keyfactor Command remote agent written
in C, aimed at IoT and embedded Linux deployments. The agent registers
a session with the Keyfactor Command platform, runs any PEM inventory,
management, or reenrollment jobs the platform assigns, and exits.

Current version: **3.0.0.0** (see
[`agent.h`](agent.h)). Supported crypto backends:

- OpenSSL
- wolfSSL
- OpenSSL + `tpm2tss` engine (TPM-backed private keys)

## Quick start

```bash
# 1. Install host dependencies (Debian/Ubuntu example).
sudo apt update
sudo apt install -y build-essential git curl libcurl4-gnutls-dev libssl-dev

# 2. Clone and build against OpenSSL (64-bit host).
git clone https://github.com/keyfactor-iot/Keyfactor-CAgent ~/Keyfactor-CAgent
cd ~/Keyfactor-CAgent
make clean
make CRYPTO=openssl OUT=exec -j$(nproc)

# 3. Set up trust store and config.
sudo mkdir -p /home/keyfactor/Keyfactor-CAgent/certs
sudo chown $(whoami):$(whoami) /home/keyfactor/Keyfactor-CAgent/certs
$EDITOR /home/keyfactor/Keyfactor-CAgent/certs/trust.store   # paste PEM CA bundle
cp config.json.example config.json                           # or create from the template in docs/configuration.md
$EDITOR config.json                                          # set Hostname, AgentName, credentials, cert paths

# 4. Run.
./agent -l i
```

For wolfSSL, 32-bit targets, shared-library packaging, and TPM builds,
see [`docs/build.md`](docs/build.md).

## Documentation

The `docs/` directory contains the full, code-derived documentation:

| Document                                                             | Purpose |
|----------------------------------------------------------------------|---------|
| [`docs/overview.md`](docs/overview.md)                               | What the agent is, supported capabilities, session lifecycle at a glance, non-goals. |
| [`docs/installation.md`](docs/installation.md)                       | Host prerequisites (Debian/Ubuntu, RHEL family) and how to clone the repo. |
| [`docs/build.md`](docs/build.md)                                     | Every `makefile` target (OpenSSL, wolfSSL, shared library, TPM), 32-bit vs 64-bit, build flags. |
| [`docs/configuration.md`](docs/configuration.md)                     | Full `config.json` reference aligned to the in-code `ConfigData_t`, trust store setup, `ClientParameterPath` / `params.json` explained. |
| [`docs/cli.md`](docs/cli.md)                                         | Command-line switches (`-a`, `-c`, `-e`, `-h`, `-l`, `-v`, `-?`) with examples. |
| [`docs/architecture.md`](docs/architecture.md)                       | Module-by-module map, session lifecycle, job dispatch, chained jobs, crypto abstraction, DTO layer. |
| [`docs/logging.md`](docs/logging.md)                                 | Log levels, the 5 MB rolling log file, and the self-healing `.index` sidecar. |
| [`docs/enrollment-and-certificates.md`](docs/enrollment-and-certificates.md) | Managed vs bootstrap cert flows, CSR generation, two-step first registration, cert renewal. |
| [`docs/development.md`](docs/development.md)                         | Code style, compiler flags, versioning, memory hygiene, contributing. |

## License

Apache-2.0. Full license text in
[`README-LICENSE.txt`](README-LICENSE.txt).

## Contributing

Issues and pull requests: <https://github.com/keyfactor-iot/Keyfactor-CAgent>.
See [`docs/development.md`](docs/development.md) before opening a PR.
