# Development

This page covers everything a new contributor needs to start hacking
on the agent.

## Code style

The house style for this repository is:

- K&R / LLVM base style.
- Opening brace on the same line as the control statement.
- 4-space indent, no tabs.
- Braces after functions, classes, enums, unions, and namespaces stay
  on the same line as their declarator.

Additional conventions followed consistently in-tree:

- Every `.c` and `.h` file begins with the Apache-2.0 header block.
- Every `.h` file ends with an `END OF FILE` banner comment.
- All log messages begin with `"%s::%s(%d) : "` fed by the `LOG_INF`
  macro — see [`logging.md`](logging.md).
- Each module uses `static` for file-local helpers and reserves
  non-`static` functions for its public header surface.
- `#define _POSIX_C_SOURCE 200809L` appears near the top of every
  header.

## Building locally

See [`build.md`](build.md) for the full variable reference. For
day-to-day work on an x86_64 Linux host, the OpenSSL build is the
fastest path:

```bash
make clean
make CRYPTO=openssl OUT=exec -j$(nproc)
./agent -l t   # trace-level, reads ./config.json
```

The compiler flags in the makefile are strict:

- `-Wall -Wextra -Wvla -Wshadow -Werror -pedantic`
- `-std=gnu99`
- `-fPIC`
- `-fno-strict-aliasing`

A handful of warnings are suppressed globally — read the `CFLAGS`
block in the [`makefile`](../makefile) before adding new warning
classes.

## Testing

There is no automated test suite in this repository. Verification
today is done by:

- Running the agent end-to-end against a test Keyfactor Command
  instance (see [`enrollment-and-certificates.md`](enrollment-and-certificates.md)).
- Inspecting trace-level logs (`-l t`) and the persisted `LogFile`.
- Visual review of CSR / cert outputs and inventory DTOs.

`.github/workflows/` exists in the tree but is empty — there is no
CI configured.

## Versioning

The four-part version number is compiled in via
[`agent.h`](../agent.h):

```c
#define AGENT_MAJOR 3ULL
#define AGENT_MINOR 0ULL
#define AGENT_MICRO 0ULL
#define AGENT_BUILD 0ULL
```

These are packed into a single `uint64_t` `AGENT_VERSION` that is sent
on every `/Session/Register` call and printed by the `--help` banner.
Bump whichever fields fit the release semantics before tagging.

## Submodules and libraries

Third-party code lives under [`lib/`](../lib/):

- `lib/json.{c,h}` — ccan JSON, Joseph Adams; modified 2025-12-05 for
  C99 pedantic compliance (named the anonymous union). No upstream
  sync — treat as vendored.
- `lib/base64.{c,h}` — Matt Gallagher; lightly modified for POSIX.1
  compliance in 2025-12-05.

Neither is a git submodule. If you need to pull in upstream changes,
re-apply the local patches by hand.

## Memory hygiene

The agent targets IoT hardware with modest RAM. A few rules from the
codebase:

- Every DTO has matching `_new` / `_free` helpers; always free on exit
  paths.
- `ClientParameter_t` ownership transfers when appended to
  `SessionRegisterReq_t.ClientParameters[]` — the container frees
  them.
- `SessionRegisterResp_t` holds a separate `Jobs` array;
  `SessionRegisterResp_free()` does **not** free jobs that have been
  transferred onto the schedule list. That is the job of
  `SessionRegisterResp_freeJobs()` and `clear_job_schedules()`.

When editing, run under `valgrind` — the repo `.gitignore` already
excludes `valgrind.log` and `valgrind_output/`, so it is expected.

## Contributing

Issues and pull requests are welcome at
<https://github.com/Keyfactor/Keyfactor-CAgent>.

Before opening a PR:

- Run `make clean` and build the target(s) your change affects. The
  makefile treats warnings as errors — a warning will block the build
  and thus block review.
- Keep changes focused. Unrelated refactors should be separate PRs.
- Match the existing style in files you touch.
- If you touch the public config surface, update
  [`configuration.md`](configuration.md) and the validation logic in
  `config.c` in the same PR.

## License

The project is Apache-2.0. The full text is in
[`README-LICENSE.txt`](../README-LICENSE.txt) at the repo root.
