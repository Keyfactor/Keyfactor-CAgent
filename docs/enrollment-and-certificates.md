# Enrollment and certificates

This page covers two orthogonal concerns:

- **Authentication modes** — how the agent proves its identity to
  Keyfactor Command.
- **Cert postures** — how the agent obtains and rotates the
  certificate it uses in modes 1 and 2.

Configuration fields referenced here are documented in
[`configuration.md`](configuration.md); command-line flags are
documented in [`cli.md`](cli.md).

## Authentication modes

The agent supports three working modes plus a fourth that is planned
on the Keyfactor side but not yet implemented.

| # | Mode                                   | `UseAgentCert` | `-a` CLI flag | Credentials           |
|---|----------------------------------------|----------------|---------------|-----------------------|
| 1 | mTLS terminated by a reverse proxy     | `true`         | **off**       | Agent cert (TLS handshake) |
| 2 | mTLS with agent-injected header (`-a`) | `true`         | **on**        | Agent cert (TLS + header) |
| 3 | Basic auth, no agent certificate       | `false`        | off           | `Username` / `Password`    |
| 4 | OAuth                                  | —              | —             | *not yet implemented* |

Modes 1 and 2 are **mutually exclusive** — in both cases the agent
cert ends up as an `X-ARR-ClientCert` header at Keyfactor; the
difference is who writes that header. Enabling both at the same time
produces conflicting headers and unpredictable behaviour.

### Mode 1 — mTLS terminated by a reverse proxy

**Deployment shape:** a reverse proxy (IIS with ARR, nginx, etc.)
sits in front of Keyfactor Command. The proxy terminates the TLS
session, validates the client certificate itself, and forwards the
used cert to Keyfactor in an HTTP header on the agent's behalf.

**Agent config:**

- `UseAgentCert = true`
- `AgentCert` / `AgentKey` populated (the cert the proxy will see).
- `VirtualDirectory` points at the virtual directory the proxy maps
  to `KeyfactorAgents`.
- `Username` / `Password` omitted.

**CLI:** run the agent **without** `-a`.

**On the wire:** the agent performs a standard mTLS handshake against
the proxy URL. No extra HTTP header is added.

**Enrollment:** standard managed-cert flow — see
[First-time enrollment](#first-time-enrollment) below. A CSR is
generated on first run; the platform returns the signed cert; the
agent saves it and flips `EnrollOnStartup` to `false`.

**What breaks if you get it wrong:** passing `-a` will cause the
agent to self-inject the cert into `X-ARR-ClientCert` — the proxy
will then overwrite (or conflict with) that header, depending on its
configuration.

### Mode 2 — mTLS with agent-injected header (`-a`)

**Deployment shape:** no reverse proxy between the agent and
Keyfactor, or a proxy that does **not** do cert-to-header injection.
The agent is responsible for making sure Keyfactor sees the client
certificate in the expected header.

**Agent config:** identical to mode 1 — `UseAgentCert = true`, cert
and key paths populated, no basic-auth credentials.

**CLI:** run the agent **with** `-a`.

**On the wire:** the agent presents its cert via the TLS handshake
**and** URL-encodes the same PEM into the `X-ARR-ClientCert` HTTP
header on every request. This is handled in `build_request_headers()`
at [`httpclient.c:362`](../httpclient.c). The header name is
`CLIENT_CERT_HEADER` in [`httpclient.h`](../httpclient.h).

**Enrollment:** identical to mode 1.

**What breaks if you get it wrong:** passing `-a` with
`UseAgentCert = false` is effectively a no-op — `certBytes` will be
NULL in `build_request_headers()` and the header will not be sent;
the agent will fall back to whatever other credentials are configured
(or fail authentication).

### Mode 3 — Basic authentication, no agent certificate

**Deployment shape:** identity is established by a
domain-qualified username and password rather than a client
certificate. Keyfactor Command accepts the credentials directly over
1-way TLS.

**Agent config:**

- `UseAgentCert = false`
- `Username` (escaped as `DOMAIN\\user`) and `Password` populated.
- Agent cert fields (`AgentCert`, `AgentKey`, `CSRSubject`,
  `CSRKeyType`, `CSRKeySize`) may be omitted.

**CLI:** `-a` has no effect; omit it.

**On the wire:** 1-way TLS (the agent still trusts the platform via
`TrustStore`) with HTTP Basic auth carried by libcurl.

**Enrollment:** `prepare_enrollment()` in
[`session.c`](../session.c) takes the no-cert branch:

```c
if (ConfigData->EnrollOnStartup) {
    ...
    if (ConfigData->UseAgentCert) {
        register_agent(sessionReq);   /* generates keypair + CSR */
    } else {
        log_trace("%s::%s(%d) : Configured to not use an Agent Certificate", LOG_INF);
    }
}
```

No keypair is generated and no CSR is submitted. After the first
successful `/Session/Register`, `update_config_from_session()` at
[`session.c:146`](../session.c) notices `UseAgentCert == false`,
flips `EnrollOnStartup` to `false`, and persists that change — the
same way it does for cert-based modes when a signed cert comes back.

### Mode 4 — OAuth (planned)

OAuth authentication is a Keyfactor-side TODO. The C-agent does not
have OAuth code today — there are no bearer-token or OAuth flow
primitives in the source tree. This section is a placeholder; it
will be filled in when the platform and agent support ships.

## Cert postures

The sections below describe how the agent obtains and rotates the
certificate it uses in modes 1 and 2. Two postures are supported:

- **Managed agent certificate** (`UseAgentCert=true`,
  `UseBootstrapCert=false`) — default. The agent generates its own
  key + CSR on first run, the platform signs it, and the managed cert
  is used on every subsequent call.
- **Bootstrap-then-rotate** (`UseAgentCert=true`,
  `UseBootstrapCert=true`) — the first `/Session/Register` is
  authenticated with a pre-provisioned bootstrap cert. The platform
  issues a new managed cert that replaces the bootstrap cert for
  future calls. See [Bootstrap flow](#bootstrap-flow).

Mode 3 does not use a managed cert; mode 4 is not yet implemented.

## First-time enrollment

Entry point: `register_session()` in [`session.c`](../session.c).

When `EnrollOnStartup=true`, the agent runs
`prepare_enrollment()` → `register_agent()`:

1. **Generate a keypair.** `generate_keypair()` in [`csr.c`](../csr.c)
   calls either `ssl_generate_rsa_keypair()` or
   `ssl_generate_ecc_keypair()` on the active SSL wrapper, using
   `CSRKeyType` + `CSRKeySize` from config. ECC sizes are restricted
   to 256, 384, or 521.
2. **Generate a CSR.** `generate_csr()` calls `ssl_generate_csr()` with
   the `CSRSubject` from config (or the hostname-derived subject when
   `-h` was passed). The CSR is base64-DER encoded for transport.
3. **Build the registration request.** The CSR is attached to
   `SessionRegisterReq_t.CSR`; capabilities (the three PEM GUIDs), the
   tenant ID, the agent version, and any `ClientParameterPath` members
   are folded in.
4. **POST to `/Session/Register`.** Authentication depends on
   `UseBootstrapCert`:
   - `false` → username/password from config (if set).
   - `true` → bootstrap cert + key (see
     [Bootstrap flow](#bootstrap-flow)).

### Two-step first registration

The platform responds to the first registration with an
`AgentId` + `Token` but **no jobs** — the platform still has to
approve the agent and mint its signed certificate. `session.c` then
performs a second `/Session/Register`:

```
register_session()
 ├── first POST  → AgentId + Token (no jobs yet)
 ├── finalize_first_registration()
 │    └── do_second_registration()
 │         └── second POST  → receives the signed cert + initial job list
 ├── handle_token_response() → schedules the jobs
 └── EnrollOnStartup is flipped to false on success, persisted to disk
```

Once the second call succeeds, `ConfigData->EnrollOnStartup = false`
is written back via `config_save()`. Subsequent runs skip enrollment
and go straight to session registration with the managed cert.

### Persisting the signed cert

When the platform returns a signed PEM in the registration response,
`save_cert_key()` in [`csr.c`](../csr.c) writes the cert and the
generated private key to `AgentCert` / `AgentKey` respectively via
`ssl_save_cert_key()`. An optional `AgentKeyPassword` is applied if
supplied.

## Subsequent runs

When `EnrollOnStartup=false`:

1. `prepare_enrollment()` calls `is_cert_active(ConfigData->AgentCert)`
   which checks the on-disk cert's validity window via the active SSL
   wrapper's `ssl_is_cert_active()`.
2. If the cert is valid, the agent sends a `/Session/Register` request
   authenticated with the cert (mTLS) and proceeds to the job list.
3. If the cert has expired, `reset_agent()` is invoked — this clears
   session state and flips `EnrollOnStartup` back to `true`, so the
   next run performs a fresh enrollment.

### Cert renewal triggered by the platform

If the platform returns error codes `A0100007` or `A0100008`
(`is_cert_renewal_error()` in `session.c`), the agent enters
`re_register_agent()` which generates a fresh CSR and submits it,
effectively rolling the cert without dropping the session.

## Bootstrap flow

Set in `config.json`:

```json
{
    "UseAgentCert": true,
    "UseBootstrapCert": true,
    "BootstrapCert": "/path/to/bootstrap.pem",
    "BootstrapKey":  "/path/to/bootstrap.key",
    "BootstrapKeyPassword": "optional",
    "EnrollOnStartup": true,
    "AgentCert": "/path/to/Agent-cert.pem",
    "AgentKey":  "/path/to/Agent-key.pem"
}
```

During first registration:

- `http_post_json()` in [`httpclient.c`](../httpclient.c) is handed
  the bootstrap cert and key instead of the (empty) agent cert/key.
- The platform validates the bootstrap cert and issues the agent's
  signed cert back in the second-registration response.
- `save_cert_key()` writes the new cert/key to `AgentCert` / `AgentKey`.
- From the second run onwards the bootstrap cert is no longer
  presented; the managed cert is used. You may delete the bootstrap
  cert/key once you have confirmed enrollment succeeded.

Validation in `config.c` will refuse to start the agent if
`UseBootstrapCert=true` without both `BootstrapCert` and `BootstrapKey`
populated.

## Trust store

Regardless of posture, the agent always needs a valid `TrustStore`
pointing at a PEM bundle. libcurl appends these to the host trust
store when building the TLS context. Include:

- The platform's server certificate (or its issuing CA).
- Any intermediates in the chain.

The file must use standard PEM framing
(`-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----`).

## `X-ARR-ClientCert` header mechanics

The header that carries the client certificate to Keyfactor Command
is written by one of two parties, depending on the authentication
mode:

- **Mode 1** — the reverse proxy writes it after validating the
  mTLS handshake. The agent **must not** also inject it.
- **Mode 2** — the agent writes it itself from `-a`. Use only when
  there is no proxy doing the injection.

Agent-side injection lives in `build_request_headers()` at
[`httpclient.c:362`](../httpclient.c). It fires only when both
`add_client_cert_to_header` is true (set by `-a`) and a populated
cert is available (`UseAgentCert=true` with `AgentCert` loaded). The
header name itself is `CLIENT_CERT_HEADER` in
[`httpclient.h`](../httpclient.h).

## TPM-backed keys

On TPM builds (`rpi9670test`), `ssl_generate_rsa_keypair()` takes an
extra `path` argument identifying the TPM key file:

```c
bool generate_keypair(const char* keyType, int keySize, const char* path);
```

The private key material stays inside the TPM; the agent holds a
handle to it. `AgentKeyPassword` in config is required in this case —
it is the pass-phrase the tpm2tss engine uses to unlock the key. See
[`build.md`](build.md) for the build and `-e` switch usage.
