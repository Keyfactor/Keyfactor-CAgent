# Configuration

The agent reads its configuration from a JSON file. By default that file
is `config.json` in the current working directory; it can be overridden
with the `-c` command-line switch (see [`cli.md`](cli.md)).

This reference matches the in-code `ConfigData_t` struct declared in
[`config.h`](../config.h) and parsed in `parse_config_fields()` in
[`config.c`](../config.c). **Field names are case-sensitive.**

## Example

```json
{
    "AgentId": "",
    "AgentName": "UniqueName",
    "Hostname": "www.yourtestdrive.com",
    "Username": "testdrive\\yourusername",
    "Password": "yourpassword",
    "VirtualDirectory": "KeyfactorAgents",
    "TrustStore": "/home/keyfactor/Keyfactor-CAgent/certs/trust.store",
    "UseAgentCert": true,
    "AgentCert": "/home/keyfactor/Keyfactor-CAgent/certs/Agent-cert.pem",
    "AgentKey":  "/home/keyfactor/Keyfactor-CAgent/certs/Agent-key.pem",
    "CSRKeyType": "ECC",
    "CSRKeySize": 256,
    "CSRSubject": "CN=UniqueName",
    "EnrollOnStartup": true,
    "UseSsl": true,
    "LogFile": "agent.log"
}
```

## Minimal config per authentication mode

The agent supports three working authentication modes (plus OAuth,
which is planned but not yet implemented). The shape of `config.json`
differs per mode. See
[`enrollment-and-certificates.md`](enrollment-and-certificates.md#authentication-modes)
for what each mode does on the wire.

### Mode 1 — mTLS terminated by a reverse proxy

A reverse proxy fronts Keyfactor Command, terminates the TLS session,
and forwards the used client cert to Keyfactor as a header. The agent
does ordinary mTLS against the proxy.

```json
{
    "AgentName": "UniqueName",
    "Hostname": "proxy.example.com",
    "VirtualDirectory": "KeyfactorAgents",
    "TrustStore": "/home/keyfactor/Keyfactor-CAgent/certs/trust.store",
    "UseAgentCert": true,
    "AgentCert": "/home/keyfactor/Keyfactor-CAgent/certs/Agent-cert.pem",
    "AgentKey":  "/home/keyfactor/Keyfactor-CAgent/certs/Agent-key.pem",
    "CSRKeyType": "ECC",
    "CSRKeySize": 256,
    "CSRSubject": "CN=UniqueName",
    "EnrollOnStartup": true,
    "UseSsl": true,
    "LogFile": "agent.log"
}
```

**CLI:** `./agent` (do **not** pass `-a`).

### Mode 2 — mTLS with agent-injected header (`-a`)

No proxy is doing cert-to-header injection, so the agent writes the
`X-ARR-ClientCert` header itself. `config.json` is identical to
mode 1:

```json
{
    "AgentName": "UniqueName",
    "Hostname": "keyfactor.example.com",
    "VirtualDirectory": "KeyfactorAgents",
    "TrustStore": "/home/keyfactor/Keyfactor-CAgent/certs/trust.store",
    "UseAgentCert": true,
    "AgentCert": "/home/keyfactor/Keyfactor-CAgent/certs/Agent-cert.pem",
    "AgentKey":  "/home/keyfactor/Keyfactor-CAgent/certs/Agent-key.pem",
    "CSRKeyType": "ECC",
    "CSRKeySize": 256,
    "CSRSubject": "CN=UniqueName",
    "EnrollOnStartup": true,
    "UseSsl": true,
    "LogFile": "agent.log"
}
```

**CLI:** `./agent -a` — the `-a` switch is what distinguishes mode 2
from mode 1 at runtime.

### Mode 3 — Basic authentication, no agent certificate

`UseAgentCert` is false. Identity is carried by the
`Username` / `Password` pair. Agent-cert fields may be omitted.

```json
{
    "AgentName": "UniqueName",
    "Hostname": "keyfactor.example.com",
    "VirtualDirectory": "KeyfactorAgents",
    "TrustStore": "/home/keyfactor/Keyfactor-CAgent/certs/trust.store",
    "UseAgentCert": false,
    "Username": "KEYFACTOR\\Administrator",
    "Password": "yourpassword",
    "EnrollOnStartup": true,
    "UseSsl": true,
    "LogFile": "agent.log"
}
```

**CLI:** `./agent` (passing `-a` is a no-op when `UseAgentCert=false`).

## Field reference

### Platform / endpoint

| Field              | Type   | Required                              | Default | Notes                                                                 |
|--------------------|--------|---------------------------------------|---------|-----------------------------------------------------------------------|
| `Hostname`         | string | Yes (minimum 7 characters)            | —       | FQDN or IP of the Keyfactor Command platform.                         |
| `VirtualDirectory` | string | Required in practice                  | —       | Typically `KeyfactorAgents`; set to the reverse-proxy virtual dir if one fronts the platform. |
| `UseSsl`           | bool   | Yes                                   | `true`  | `true` → `https://`, `false` → `http://`. Keep `true` in production.  |
| `Username`         | string | Optional                              | —       | Domain-qualified username for basic auth (remember to escape `\` as `\\`). Omit if a reverse proxy injects auth. |
| `Password`         | string | Optional                              | —       | Plain-text password for basic auth. Omit if a reverse proxy injects auth. |

Validation lives in `minimum_config_requirements()` in `config.c`:
`AgentName` and `Hostname` are checked for length; missing `Hostname` or
a hostname shorter than 7 characters is a fatal error.

### Agent identity

| Field                   | Type   | Required                | Default | Notes |
|-------------------------|--------|-------------------------|---------|-------|
| `AgentId`               | string | Yes (empty string allowed) | —    | Populated by the platform during registration. Leave `""` on first install. The agent validates the field on load — see `validate_and_fix_agent_id()`. |
| `AgentName`             | string | Yes                     | —       | Unique friendly name. If you pass `-h` on the CLI, the agent sets this to `$HOSTNAME_YYYYMMDDHHMMSS` at runtime and ignores the config value. |
| `ClientParameterPath`   | string | Optional                | —       | Path to a JSON object whose members are folded into the `/Session/Register` request as client parameters. See [Client parameters](#client-parameters) below. |

### mTLS / agent certificate

These fields govern how the agent authenticates to Keyfactor Command.
The agent supports **four authentication modes** — see
[`enrollment-and-certificates.md`](enrollment-and-certificates.md#authentication-modes)
for the full matrix. Three of them are implemented and use the fields
below (plus the `-a` CLI switch for mode 2). The fourth, OAuth, is
not yet implemented.

| Field              | Type    | Required when `UseAgentCert=true` | Default | Notes |
|--------------------|---------|-----------------------------------|---------|-------|
| `UseAgentCert`     | bool    | —                                 | `true`  | `true` → agent uses its own cert for mTLS. `false` → 1-way TLS only. |
| `TrustStore`       | string  | Yes                               | —       | Path to a PEM bundle of additional CAs the agent trusts. Appended to the host trust store. |
| `AgentCert`        | string  | Yes                               | —       | Path where the agent's PEM cert lives. Its parent directory must exist. |
| `AgentKey`         | string  | Yes                               | —       | Path where the agent's private key lives. Its parent directory must exist. |
| `AgentKeyPassword` | string  | Optional                          | —       | Pass-phrase for the key. **Required** when a TPM / secure element is in use. |
| `CSRKeyType`       | string  | Yes                               | —       | `ECC`, `ECDSA`, or `RSA`. |
| `CSRKeySize`       | integer | Yes                               | `0`     | For ECC/ECDSA: **256, 384, or 521** only (enforced in `keypair_sanity_check()`). RSA accepts any reasonable size. |
| `CSRSubject`       | string  | Yes (minimum 4 characters, e.g. `CN=x`) | — | Used on first enrollment. Ignored when `-h` is passed on the CLI. |

### First-time enrollment / bootstrap

| Field                   | Type   | Required when bootstrap is in use | Default | Notes |
|-------------------------|--------|-----------------------------------|---------|-------|
| `EnrollOnStartup`       | bool   | Yes                               | `false` | `true` → generate a keypair and CSR and register with the platform. The agent **rewrites this to `false`** in `config.json` after first successful registration (see `finalize_first_registration()` in `session.c`). |
| `UseBootstrapCert`      | bool   | —                                 | `false` | `true` → use a pre-provisioned bootstrap certificate to authenticate the first registration call. |
| `BootstrapCert`         | string | Yes if `UseBootstrapCert=true`    | —       | Path to the bootstrap PEM cert. |
| `BootstrapKey`          | string | Yes if `UseBootstrapCert=true`    | —       | Path to the bootstrap private key. |
| `BootstrapKeyPassword`  | string | Optional                          | —       | Pass-phrase for the bootstrap key. |

See [`enrollment-and-certificates.md`](enrollment-and-certificates.md) for
the full flow.

### HTTP behavior

| Field           | Type    | Required | Default | Notes                                          |
|-----------------|---------|----------|---------|------------------------------------------------|
| `httpRetries`   | integer | Yes      | `1`     | Number of HTTP attempts before giving up. Minimum of 1 is enforced on load. |
| `retryInterval` | integer | Yes      | `1`     | Seconds between retries.                       |

### Logging

| Field     | Type   | Required | Default | Notes                              |
|-----------|--------|----------|---------|------------------------------------|
| `LogFile` | string | Yes      | —       | Path to the on-disk log file. A sibling `<LogFile>.index` is managed automatically by `logging.c`. See [`logging.md`](logging.md). |

`LogFileIndex` is **no longer** a configuration field. If you find it in
an older `config.json`, it will be ignored; the agent persists the log
write position in `<LogFile>.index` instead.

## Client parameters

`ClientParameterPath` points at a JSON object. When it is set,
`SessionRegisterReq_new()` in [`dto.c`](../dto.c) opens the file, parses
each top-level key/value pair, and appends it to the
`ClientParameters` array on the `/Session/Register` POST body.

The repository ships a minimal reference example at
[`params.json`](../params.json):

```json
{"Model": "Keyfactor"}
```

That results in a single client parameter with key `Model` and value
`Keyfactor` being sent to the platform during registration.

Values must be simple strings; nested objects and arrays are not
interpreted as client parameters.

## Trust store

The `TrustStore` file is a plain PEM bundle — one or more
`-----BEGIN CERTIFICATE-----` blocks concatenated. These are appended to
the host's CA store for HTTPS connections the agent initiates.

Typical setup:

```bash
sudo mkdir -p /home/keyfactor/Keyfactor-CAgent/certs
sudo chown $(whoami):$(whoami) /home/keyfactor/Keyfactor-CAgent/certs
$EDITOR /home/keyfactor/Keyfactor-CAgent/certs/trust.store
# paste the PEM-encoded certs for the platform and any intermediates
```

`AgentCert` and `AgentKey` live in the same directory by convention —
the parent directory must already exist when the agent starts, or
`validate_cert_file_path()` will fail and the agent will refuse to run.

## Validation behaviour

`validate_configuration()` in `config.c` runs after logging is up and
enforces:

- `AgentName` is non-empty; `AgentId` field exists (empty string OK).
- `Hostname` is non-empty and at least 7 characters.
- If `UseAgentCert=true`: `CSRSubject`, `AgentCert`, `AgentKey` present;
  `CSRSubject` at least 4 characters; parent directories for
  `AgentCert` and `AgentKey` exist.
- If `UseBootstrapCert=true`: `BootstrapCert` and `BootstrapKey` present.
- `CSRKeyType` is one of `RSA`, `ECC`, `ECDSA`; for ECC/ECDSA the
  `CSRKeySize` is 256, 384, or 521.

Any failure logs an error and causes `init_platform()` to return 0,
which terminates the agent with a failure exit code.

## Config file rewrites

The agent may rewrite `config.json` at runtime:

- After first successful registration, `EnrollOnStartup` is set to
  `false`.
- After successful second registration (re-enrollment setup),
  `EnrollOnStartup` stays `false`; on failure it is reset to `true`.
- When the `-h` CLI switch is used, the derived `$HOSTNAME_$DATETIME`
  value is persisted back to `AgentName`.

If you template the file, expect the agent to own these fields.
