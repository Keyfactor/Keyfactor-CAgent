# Logging

All log output is produced by the handful of `log_*` macros declared in
[`logging.h`](../logging.h) and implemented in
[`logging.c`](../logging.c). The same message is emitted to stdout (if
the level is enabled) and to an in-memory buffer that is flushed to
`LogFile` on shutdown.

## Log levels

Listed from loudest to quietest. Each level includes all levels below
it (closer to "off").

| API                 | CLI code (`-l`) | Prefix        |
|---------------------|-----------------|---------------|
| `log_trace()`       | `t`             | `[TRACE]`     |
| `log_debug()`       | `d`             | `[DEBUG]`     |
| `log_verbose()`     | `v`             | `[VERBOSE]`   |
| `log_info()`        | `i` (default)   | `[INFO]`      |
| `log_warn()`        | `w`             | `[WARN]`      |
| `log_error()`       | `e`             | `[ERROR]`     |
| *(off)*             | `o`             | — (no output) |

Toggling the level is done via `log_set_*()` functions or the `-l`
switch (see [`cli.md`](cli.md)). The getters `is_log_trace()`, etc. are
used in hot-path code to skip expensive formatting when the level is
disabled.

## `LOG_INF` helper

Every call site prefixes itself with file, function, and line via the
`LOG_INF` macro:

```c
#define LOG_INF __FILE__, __func__, __LINE__
```

This feeds the first three printf arguments of the log macros, which
reserve the format string `"%s::%s(%d) : "` at the start of every
message. Keep that in mind when reading raw log output.

## On-disk log file

`LogFile` in `config.json` names the on-disk file. It is a **rolling
5 MB file** — the exact limit lives in `logging.c`:

```c
#define MAX_FILE_SIZE   (5ul * 1024ul * 1024ul)
```

Writes are position-based, not line-based: when the write position
reaches `MAX_FILE_SIZE` it wraps to the beginning of the file and
starts overwriting the oldest data. This keeps disk usage bounded
without requiring log rotation tools.

The in-memory buffer is only written out at shutdown — see
`write_log_file()` called from `cleanup_logs()` in `agent.c`. If the
process is killed before cleanup runs, any messages in the buffer are
lost. Run with `-l i` or higher when you need stdout-level durability.

## `.index` persistence

Because the log file is a circular buffer, the agent needs to remember
where the next write goes. That position is persisted in a sidecar
file named `<LogFile>.index` — for example `agent.log.index` next to
`agent.log`.

The file is a single-line plain-text integer:

```
500000
```

and is easy to inspect or edit by hand.

### Why not store it in `config.json`?

It used to live in a `LogFileIndex` config field. Two pain points
motivated the split:

- Config resets dropped the index and silently caused the agent to
  overwrite existing log data.
- Manual edits to `config.json` could corrupt both configuration and
  log state.

The current design makes the sidecar file the **single source of
truth** for the write position. `config.json` is configuration only.

### Self-healing

On startup, `validate_and_correct_log_index()` in `logging.c`
reconciles three numbers:

- The index read from `<LogFile>.index` (`load_log_index()`), defaulting
  to `0` if missing.
- The actual on-disk size of `LogFile`.
- The `MAX_FILE_SIZE` ceiling.

It applies the following rules:

| Scenario                                                       | Action                                                           |
|----------------------------------------------------------------|------------------------------------------------------------------|
| Log file < `MAX_FILE_SIZE`, index = 0, file has real data     | Auto-correct index to end-of-file. Resumes without data loss.    |
| Log file < `MAX_FILE_SIZE`, index > file size                 | File was truncated. Auto-correct to end-of-file.                 |
| Log file ≥ `MAX_FILE_SIZE`, index within range                | Trust the index. Circular-buffer position is valid.              |
| Log file ≥ `MAX_FILE_SIZE`, index = 0 (sidecar lost)          | Warn and start at 0. May overwrite older data.                   |
| Index > `MAX_FILE_SIZE`                                       | Reset to 0 to prevent buffer corruption.                         |

After every write flush, `save_log_index()` rewrites
`<LogFile>.index` with the new position.

## Migration from older agents

Pre-3.x releases stored `LogFileIndex` in `config.json`. This agent
ignores that field on load and does not write it on save. If you need
the old value to carry over, create the sidecar file by hand **before**
first upgrade run:

```bash
echo "12345" > /path/to/agent.log.index
```

Otherwise the self-healing logic will pick a safe starting point on
first run.

## Maintenance

```bash
# Start fresh.
rm /path/to/agent.log /path/to/agent.log.index

# Reset the write position to the beginning without deleting the log.
echo "0" > /path/to/agent.log.index
```

Always remove (or update) the `.index` sidecar when you delete the log
file — if you leave a stale index pointing into a log that no longer
exists, the agent will warn and recover, but it is clearer to delete
both together.

## Thread safety

The logger is not thread-safe. The agent is single-threaded by design,
so this has not been an issue. If multi-threading is added, the
`.index` read/write and the buffer append would need locking.
