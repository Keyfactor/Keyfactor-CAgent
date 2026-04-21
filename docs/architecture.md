# Architecture

The agent is organised as a thin entry-point that wires together five
loosely-coupled subsystems: configuration, logging, HTTP transport,
crypto abstraction, and job scheduling/dispatch.

This page is a code-level map. Start with
[`overview.md`](overview.md) for the conceptual introduction.

## Module map

| File                             | Responsibility                                                                 |
|----------------------------------|--------------------------------------------------------------------------------|
| [`agent.c` / `agent.h`](../agent.c)                     | Entry point, CLI parsing, initialisation sequence, main job loop, chained-job dispatch, version macros. |
| [`config.c` / `config.h`](../config.c)                  | Load / save `config.json`, validate fields, build platform URLs, free configuration memory. |
| [`session.c` / `session.h`](../session.c)               | Build and POST `/Session/Register`, handle first-enroll vs re-register, persist session state. |
| [`schedule.c` / `schedule.h`](../schedule.c)            | Priority-ordered linked list of scheduled jobs, reschedule, one-time job removal. |
| [`inventory.c` / `inventory.h`](../inventory.c)         | Handler for `CertStores.PEM.Inventory` jobs (`cms_job_inventory`). |
| [`management.c` / `management.h`](../management.c)      | Handler for `CertStores.PEM.Management` jobs (`cms_job_manage`). |
| [`enrollment.c` / `enrollment.h`](../enrollment.c)      | Handler for `CertStores.PEM.Reenrollment` jobs (`cms_job_enroll`). |
| [`csr.c` / `csr.h`](../csr.c)                           | Keypair generation and CSR assembly (routes to the active SSL wrapper). |
| [`httpclient.c` / `httpclient.h`](../httpclient.c)      | libcurl wrapper: retries, mTLS, optional `X-ARR-ClientCert` injection. |
| [`dto.c` / `dto.h`](../dto.c)                           | JSON (de)serialisation of every request/response DTO; also manages `ClientParameter_t` arrays. |
| [`logging.c` / `logging.h`](../logging.c)               | In-memory log buffer, level gating, on-disk rolling log, `.index` persistence. |
| [`utils.c` / `utils.h`](../utils.c)                     | File helpers (`read_file_bytes`, `replace_file`, `backup_file`), string helpers, path checks. |
| [`constants.h`](../constants.h)                         | Capability GUIDs, enumerations (`InventoryStatus`, `AgentApiResultStatus`, `JobCompleteStatus`, `OperationType`, `AgentPlatform`). |
| [`global.h`](../global.h)                               | Project-wide flags and globals (`__HTTP_1_1__`, engine id, UUID size). |
| [`openssl_wrapper/`](../openssl_wrapper/)               | OpenSSL implementation of the `ssl_*` abstraction. |
| [`wolfssl_wrapper/`](../wolfssl_wrapper/)               | wolfSSL implementation of the same abstraction. |
| [`lib/json.{c,h}`](../lib/json.h)                       | ccan JSON library (Joseph Adams), with small C99-pedantic tweaks. |
| [`lib/base64.{c,h}`](../lib/base64.h)                   | Base64 encode/decode (Matt Gallagher). |
| [`openssl_compat.h`](../openssl_compat.h)               | Shim for pre-1.1.0 OpenSSL `RSA_get0_key`. |

## Initialisation sequence

From `main()` → `init_platform()` in `agent.c`:

1. `parse_parameters()` — read CLI switches; defaults `config_location`
   to `config.json` if `-c` is not passed.
2. `config_load()` — read the file at `config_location` into a
   `ConfigData_t`. Returns `NULL` on any parse failure.
3. `init_logging()` / `load_log_buffer()` — allocate the in-memory log
   buffer. From this point onwards the logger writes both to stdout
   (gated by level) and to the buffer.
4. `validate_configuration()` — hard-fail if required fields are
   missing or out of range (see [`configuration.md`](configuration.md)).
5. On TPM builds only: `init_tpm_engine()` → `initialize_engine()` loads
   the named OpenSSL engine and registers it for all algorithms.
6. `init_ssl_and_curl()` — `ssl_init()` on the active wrapper plus
   `curl_global_init(CURL_GLOBAL_DEFAULT)`.

Any failure returns 0 from `init_platform()`, which flips the global
`success` flag to `false`; the agent still drops through to
`release_platform()` and `cleanup_logs()` so state and logs are
flushed.

## Session lifecycle

`register_session()` in `session.c` drives the interaction with the
platform:

```
register_session()
├── SessionRegisterReq_new(ClientParameterPath)    // dto.c
├── set_registration_parameters()                   // capabilities, TenantId, etc.
├── prepare_enrollment()
│     ├── [EnrollOnStartup && UseAgentCert] → register_agent()
│     │                                        // generates keypair + CSR
│     └── [otherwise] is_cert_active() check on existing AgentCert
├── send_session_request()
│     └── http_post_json()  → POST /Session/Register
├── (response has Token?)
│     ├── yes → handle_token_response()
│     │         ├── schedule jobs by priority (prioritize_jobs())
│     │         └── on first-enroll success → finalize_first_registration()
│     │                                         └── do_second_registration()
│     │                                              (flips EnrollOnStartup → false)
│     └── no  → handle_no_token_response()
│               └── checks for A0100007 / A0100008 cert-renewal errors;
│                   on match → re_register_agent()
```

The full list of response codes handled: `0` = OK, `997` = JSON decode
failure, `998` = setup / internal failure, plus any direct HTTP status
from libcurl.

After `register_session()` returns, control goes back to `main_loop()`
in `agent.c`, which walks `JobList` via `execute_all_jobs()`:

```c
while (currentJob) {
    if (0 != run_job(currentJob->Job)) local_success = false;
    currentJob = currentJob->NextJob;
}
```

## Job dispatch

Each element of `JobList` is a `ScheduledJob_t` (linked list) wrapping
a `SessionJob_t` DTO. `run_job()` calls `dispatch_job_by_type()`, which
compares `JobTypeId` against the three supported capability GUIDs from
`constants.h` using `strcasecmp`:

```c
CAP_PEM_INVENTORY   → cms_job_inventory()
CAP_PEM_MANAGEMENT  → cms_job_manage()
CAP_PEM_REENROLLMENT→ cms_job_enroll()
```

Any other capability GUID logs `"Unimplemented support for job type"`
and returns 0 without running.

### Chained jobs

When a handler returns 0 (success), it may also populate the
`chainJobId` out-parameter with a GUID. If `__RUN_CHAIN_JOBS__` is
defined (the default — see [`build.md`](build.md)),
`run_chain_job_if_needed()` looks that GUID up in `JobList` via
`get_job_by_id()` and invokes it immediately. This is how
Inventory → Management and Reenrollment → Inventory can be wired
server-side.

## Scheduling

`schedule.c` maintains `JobList` as a singly-linked list.

- `schedule_job()` appends a new job, **or** if a job with the same
  `JobId` is already present:
  - One-time jobs (`Schedule[0] == 'O'`) are removed and replaced.
  - Otherwise, the existing job's `NextExecution` is updated and the
    new allocation is discarded.
- `get_runnable_job()` scans forward for the first job whose
  `NextExecution <= now`.
- `get_job_by_id()` walks the list and returns by `JobId`
  (case-insensitive).
- `clear_job_schedules()` walks and frees every node and its
  `SessionJob_t` payload.

Priority ordering of the initial list is built in `prioritize_jobs()`
in `session.c` based on `SessionJob_t.Priority`.

## Crypto abstraction

Both `openssl_wrapper/openssl_wrapper.h` and
`wolfssl_wrapper/wolfssl_wrapper.h` expose the same `ssl_*` API. Which
one is linked is a compile-time choice (`-D__OPEN_SSL__` or
`-D__WOLF_SSL__`). The shared surface:

```
ssl_init, ssl_cleanup
ssl_seed_rng
ssl_generate_rsa_keypair, ssl_generate_ecc_keypair
ssl_generate_csr
ssl_save_cert_key
ssl_read_store_inventory
ssl_PemInventoryItem_create
ssl_Store_Cert_add
ssl_remove_cert_from_store
ssl_is_cert_active
PemInventoryItem_free, PemInventoryList_free
```

`PemInventoryItem` / `PemInventoryList` are defined identically in both
headers — they carry the PEM text, a SHA-1 thumbprint string, and a
`has_private_key` flag.

On TPM builds, `ssl_generate_rsa_keypair` takes an extra `file`
argument that names the TPM-backed key file; the key itself never
leaves the TPM.

## DTO / JSON layer

`dto.c` owns every struct exchanged with the platform:

- Session: `SessionRegisterReq_t`, `SessionRegisterResp_t`, with
  `ClientParameter_t` arrays.
- Common: `CommonConfigReq_t`, `CommonCompleteReq_t`,
  `CommonCompleteResp_t` — used to fetch a job's config from its
  `ConfigurationEndpoint` and to report completion on its
  `CompletionEndpoint`.
- Per-capability: `InventoryConfigResp_t` / `InventoryUpdateReq_t` /
  `InventoryUpdateResp_t` / `InventoryCurrentItem_t` /
  `InventoryUpdateItem_t` / `InventoryUpdateList_t`,
  `ManagementConfigResp_t` / `ManagementCompleteResp_t`,
  `EnrollmentConfigResp_t` / `EnrollmentEnrollReq_t` /
  `EnrollmentEnrollResp_t` / `EnrollmentCompleteResp_t`,
  `FetchLogsConfigResp_t` / `FetchLogsCompleteReq_t`.

Each struct has matching `_new`/`_free`/`_toJson`/`_fromJson` helpers
as appropriate. The underlying parser is ccan JSON in
[`lib/json.c`](../lib/json.c).

`AgentApiResult_t` is the common envelope for all platform responses;
`AgentApiResult_log()` logs it in a uniform way and extracts a message
string and status.

## HTTP transport

`http_post_json()` in `httpclient.c` is the single network entry
point. It:

- Builds a libcurl easy handle per request.
- Honors `httpRetries` / `retryInterval` from config.
- Supports basic auth via `Username` / `Password`.
- Supplies the PEM trust store (`TrustStore`), agent cert, key, and
  optional key password for mTLS.
- When `add_client_cert_to_header` is set (via CLI `-a`), the agent's
  PEM cert is urlencoded and injected into the
  `X-ARR-ClientCert` HTTP header.
- Follows HTTP 1.1 semantics by default (`__HTTP_1_1__` is defined in
  [`global.h`](../global.h)).

## Shutdown

`release_platform()` (called unconditionally from `main()`):

1. `cleanup_jobs()` → `clear_job_schedules()`.
2. `cleanup_curl()` → `curl_global_cleanup()` if curl was initialised.
3. On TPM builds, `ENGINE_free()` on the loaded engine.
4. `ssl_cleanup()` on the active wrapper.

Then `cleanup_logs()`:

1. `write_log_file()` flushes the in-memory buffer to `LogFile`, also
   updating `<LogFile>.index`.
2. `cleanup_config()` frees `ConfigData` and `config_location`.
3. `free_log_heap()` releases the buffer.

Finally `main()` returns `EXIT_SUCCESS` if the global `success` flag is
still `true`, else `EXIT_FAILURE`.
