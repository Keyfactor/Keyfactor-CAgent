# Command-line interface

All switches are parsed by `parse_parameters()` in [`agent.c`](../agent.c).
`getopt_long()` is used, so both short and long forms are accepted.

## Synopsis

```
agent [-a] [-c config_file] [-e engine_name] [-h] [-v] [-l loglevel] [-?]
```

## Switches

| Short | Long           | Argument      | Effect |
|-------|----------------|---------------|--------|
| `-a`  | `--addheader`  | *none*        | Have the agent URL-encode its PEM certificate and inject it into the `X-ARR-ClientCert` HTTP header on every request. This is **mode 2** of the authentication matrix — see [`enrollment-and-certificates.md`](enrollment-and-certificates.md#authentication-modes). Only use `-a` when the deployment does **not** already have a reverse proxy that injects the client cert; doing both produces conflicting headers. Requires `UseAgentCert=true` and a populated agent cert — otherwise `certBytes` is NULL in `build_request_headers()` at [`httpclient.c:362`](../httpclient.c) and the header is silently not sent. The header name is set by `CLIENT_CERT_HEADER` in [`httpclient.h`](../httpclient.h). |
| `-c`  | `--config`     | *config_file* | Read configuration from *config_file* instead of the default `./config.json`. |
| `-e`  | `--engine`     | *engine_name* | Use the named OpenSSL engine for key operations. **Only meaningful on TPM builds** (see `-D__TPM__` in [`build.md`](build.md)). On non-TPM builds the switch is accepted but ignored. If omitted on a TPM build, the agent falls back to the OpenSSL `dynamic` engine. |
| `-h`  | `--hostname`   | *none*        | Override `AgentName` and `CSRSubject` at runtime using `$HOSTNAME_YYYYMMDDHHMMSS`. The derived name is persisted back to `config.json`. |
| `-v`  | `--verbose`    | *none*        | Legacy switch kept for v1.x compatibility. Equivalent to `-l v`. |
| `-l`  | `--loglevel`   | *level*       | Set the log verbosity. See the level table below. |
| `-?`  | `--help`       | *none*        | Print the usage banner and exit. |

## Log level codes

Accepted arguments to `-l`:

| Code | Level   | Includes                                     |
|------|---------|----------------------------------------------|
| `o`  | off     | No output.                                   |
| `e`  | error   | Errors only.                                 |
| `w`  | warning | Errors + warnings.                           |
| `i`  | info    | Errors + warnings + info (the default).      |
| `v`  | verbose | Errors + warnings + info + verbose.          |
| `d`  | debug   | All of the above plus debug.                 |
| `t`  | trace   | Everything, including traced libcurl output. |

Any other character falls back to `info`. See [`logging.md`](logging.md)
for how log levels interact with on-disk file size and `.index` rollover.

## Exit status

- `EXIT_SUCCESS` (0) — all scheduled jobs completed without error.
- `EXIT_FAILURE` (1) — platform initialisation failed, session
  registration failed, or at least one job handler returned a non-zero
  status. The global `success` flag in `agent.c` is set to `false` on
  the first failure and determines the exit code.

## Examples

```bash
# Default run, info logging, config.json in the current directory.
./agent -l i

# Trace-level logging, custom config path.
./agent -l t -c /etc/keyfactor/agent.json

# mTLS with the cert injected as an X-ARR-ClientCert header, error-only logging.
./agent -ahl e

# Named-hostname run (AgentName becomes $HOSTNAME_YYYYMMDDHHMMSS).
./agent -hl i

# TPM build, explicit engine name.
./agent -e tpm2tss -l i
```
