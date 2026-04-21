# Overview

The C-Agent is a reference implementation of a Keyfactor Command remote
agent written in C and intended for IoT and embedded Linux deployments. It
is a single-process program that registers a session with the Keyfactor
Command platform, retrieves a priority-ordered list of jobs, runs each
job, and exits. It is **not** a long-running daemon.

The entry point is `main()` in [`agent.c`](../agent.c) (or `KF_main()` when
built as a shared library — see [`build.md`](build.md)). The initialisation
sequence, dispatch loop, and shutdown are documented in
[`architecture.md`](architecture.md).

## Current version

The agent version is encoded as four 16-bit fields in
[`agent.h`](../agent.h):

```c
#define AGENT_MAJOR 3ULL
#define AGENT_MINOR 0ULL
#define AGENT_MICRO 0ULL
#define AGENT_BUILD 0ULL
```

At the time this document was written that yields **3.0.0.0**. The version
is reported to the platform as part of `/Session/Register` (see
`register_session` in [`session.c`](../session.c)) and is printed in the
`--help` banner.

## Supported job capabilities

The agent advertises and implements three PEM-related capabilities. Their
GUIDs are defined in [`constants.h`](../constants.h) and the text-name form
is defined in [`agent.c`](../agent.c):

| Capability             | Handler                               | GUID                                   |
|------------------------|---------------------------------------|----------------------------------------|
| `CertStores.PEM.Inventory`    | `cms_job_inventory` (inventory.c)   | `a809ce1f-1eea-4738-a38e-15708c89c981` |
| `CertStores.PEM.Management`   | `cms_job_manage` (management.c)     | `1d411b36-ae72-433f-9f3f-8593e836a1af` |
| `CertStores.PEM.Reenrollment` | `cms_job_enroll` (enrollment.c)     | `aa015d10-cffc-41f7-a9a4-c9615f6f3bdf` |

Dispatch happens in `dispatch_job_by_type()` in `agent.c`, keyed off
`SessionJob_t.JobTypeId` using `strcasecmp`.

`constants.h` also defines GUIDs for AWS / F5 / FTP / IIS / JKS / NetScaler
and PEM-Discovery capabilities. **These are declared for reference only and
are not implemented by this agent** — a job of one of those types will log
"Unimplemented support for job type" and be ignored.

## Crypto backends

The agent can be compiled against either OpenSSL or wolfSSL. Both backends
sit behind a common abstraction header, `ssl_*` functions, declared in
[`openssl_wrapper/openssl_wrapper.h`](../openssl_wrapper/openssl_wrapper.h)
and [`wolfssl_wrapper/wolfssl_wrapper.h`](../wolfssl_wrapper/wolfssl_wrapper.h).
The selection is compile-time, driven by `-D__OPEN_SSL__` or
`-D__WOLF_SSL__`. An additional `__TPM__` build uses OpenSSL with a
`tpm2tss` engine for private-key operations.

See [`build.md`](build.md) for the build matrix and
[`architecture.md`](architecture.md) for where the abstraction is called.

## Session lifecycle (high level)

1. Parse CLI args, load `config.json`, start logging — see [`cli.md`](cli.md)
   and [`configuration.md`](configuration.md).
2. Initialise libcurl and the selected SSL backend (`ssl_init`).
3. `register_session()` in `session.c`:
   - Optionally generates a keypair and CSR on first run
     (`EnrollOnStartup=true`).
   - POSTs to `/Session/Register` via `httpclient.c`.
   - Receives a session token, agent ID, and a list of jobs.
   - On first registration, performs a second `/Session/Register` call to
     pick up the platform-generated re-enrollment jobs and then flips
     `EnrollOnStartup` to `false` in the on-disk config.
4. Jobs are inserted into a priority-ordered linked list by
   `prioritize_jobs()` (see [`schedule.h`](../schedule.h) and
   [`schedule.c`](../schedule.c)).
5. `execute_all_jobs()` in `agent.c` walks the list and calls `run_job()`
   on each. Jobs may return a **chain job ID** — when
   `__RUN_CHAIN_JOBS__` is defined (the default in the `makefile`), that
   chained job is looked up and invoked immediately.
6. The agent releases all resources, flushes the log buffer to disk, and
   exits with `EXIT_SUCCESS` or `EXIT_FAILURE`.

Enrollment and certificate flow is covered in
[`enrollment-and-certificates.md`](enrollment-and-certificates.md).
Logging — including the 5 MB rolling file and `.index` persistence — is
covered in [`logging.md`](logging.md).

## Non-goals / caveats

- **Not a daemon.** The agent makes one pass through the job list and
  exits. Scheduling recurring runs (cron, systemd timer, etc.) is the
  responsibility of the host.
- **No encryption of secrets at rest.** `config.json` stores credentials
  in plain text. A full deployment is expected to encrypt these or store
  them in a trusted element — the reference implementation does not.
- **Reference scope only.** Non-PEM capabilities and non-Linux hosts are
  out of scope.
