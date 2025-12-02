# Log File Index (.index) Implementation

## Overview

This implementation adds robust persistence for the `LogFileIndex` variable using a separate `.index` file that survives configuration file resets and provides self-healing capabilities.

## Problem Solved

Previously, `LogFileIndex` was only stored in the configuration file. This caused issues when:
- Config file was reset to defaults (LogFileIndex lost)
- Config file was corrupted or deleted
- Log file existed but config had LogFileIndex = 0
- Result: Log data was overwritten or file size tracking was lost

## Solution: Single Source of Truth with .index File

### Architecture

```
┌─────────────────┐
│  config.json    │  ← Configuration only (NO LogFileIndex)
│  LogFile path   │
└─────────────────┘
         ↓
    (references)
         ↓
┌─────────────────┐
│ agent.log.index │  ← Single source of truth for write position
│     500000      │
└─────────────────┘
         ↓
    (validates)
         ↓
┌─────────────────┐
│   agent.log     │  ← Actual log file
│   (500KB data)  │
└─────────────────┘
```

### Design Principle

**Single Source of Truth**: The `.index` file is the ONLY place where `LogFileIndex` is persisted.

1. **Load**: Read from `.index` file on startup (defaults to 0 if missing)
2. **Validate**: Compare against actual log file size
3. **Auto-Correct**: Fix mismatches when safe to do so
4. **Save**: Write to `.index` file after every log write

## Implementation Details

### New Functions in logging.c

#### `load_log_index()`
- Reads `LogFileIndex` from `<LogFile>.index`
- Returns 0 if file doesn't exist
- Called during log file validation

#### `save_log_index()`
- Writes current `LogFileIndex` to `<LogFile>.index`
- Called after every log write operation
- Simple text file format: single number

#### `validate_and_correct_log_index()`
- Comprehensive validation logic
- Handles multiple scenarios (see below)
- Auto-corrects when safe
- Warns user when manual intervention needed

#### `log_file_index` (static variable)
- Local static variable in `logging.c`
- Replaces `ConfigData->LogFileIndex`
- Only persisted in `.index` file

### Changes to config.h

- **Removed** `LogFileIndex` field from `ConfigData_t` structure
- LogFileIndex is no longer part of configuration

### Changes to config.c

- **Removed** reading `LogFileIndex` from JSON
- **Removed** writing `LogFileIndex` to JSON
- Added comments noting that LogFileIndex is managed by `logging.c`
- Config file is now purely configuration, not runtime state

### Validation Logic

#### Case 1: File Hasn't Wrapped (size < MAX_FILE_SIZE)
```
Scenario: actualLogSize = 2MB, log_file_index = 0 (.index missing)
Action:   Auto-correct to 2MB (.index file was deleted)
Result:   ✅ Resumes at end of file, no data loss
```

#### Case 2: File Truncated
```
Scenario: actualLogSize = 1MB, LogFileIndex = 3MB
Action:   Auto-correct to 1MB (file was truncated)
Result:   ✅ Resumes at end of file
```

#### Case 3: Circular Buffer Active (size >= MAX_FILE_SIZE)
```
Scenario: actualLogSize = 5MB, LogFileIndex = 2MB
Action:   Trust the index (circular buffer position)
Result:   ✅ Continues circular writes correctly
```

#### Case 4: Circular Buffer + Missing .index
```
Scenario: actualLogSize = 5MB, log_file_index = 0 (.index missing)
Action:   Warn user, start at 0 (cannot auto-correct)
Result:   ⚠️  May overwrite old logs, but warns user
```

#### Case 5: Invalid Index
```
Scenario: log_file_index = 6MB (exceeds MAX_FILE_SIZE)
Action:   Reset to 0
Result:   Prevents corruption
```

## File Format

### .index File Format
```
500000
```
- Single line containing the LogFileIndex value
- Plain text, human-readable
- Can be manually edited if needed
- Located at: `<LogFile>.index`

Example:
- Log file: `/var/log/keyfactor-agent.log`
- Index file: `/var/log/keyfactor-agent.log.index`

## Benefits

### ✅ Clean Separation of Concerns
- Config file = configuration settings only
- .index file = runtime state only
- No confusion about source of truth

### ✅ Survives Config Reset
- `.index` file persists independently of config
- Auto-recovers LogFileIndex value
- No manual intervention needed (in most cases)

### ✅ Self-Healing
- Detects mismatches between .index and actual file
- Auto-corrects when safe to do so
- Comprehensive validation on every write

### ✅ Simpler Implementation
- Single source of truth (no sync needed)
- No redundant storage
- Clearer code logic

### ✅ Circular Buffer Support
- Correctly handles wrap-around scenarios
- Validates index doesn't exceed MAX_FILE_SIZE
- Warns when circular buffer + reset detected

### ✅ Transparent Operation
- Detailed logging of validation process
- Clear warnings when issues detected
- No user action required in normal cases

## Usage

### Normal Operation
No changes required. The system automatically:
1. Loads index from `.index` file (or config if missing)
2. Validates against actual file size
3. Writes logs
4. Saves index to both config and `.index` file

### Manual Recovery
If needed, you can manually edit the `.index` file:
```bash
echo "0" > /var/log/keyfactor-agent.log.index
```

### Deleting Log File
If you delete the log file, you should also delete the `.index` file:
```bash
rm /var/log/keyfactor-agent.log
rm /var/log/keyfactor-agent.log.index
```
Or the system will auto-correct on next run.

## Testing Scenarios

### Test 1: .index File Deleted with Existing Log
```
1. Run agent, create 500KB of logs
2. Delete .index file
3. Run agent again
Expected: Auto-corrects to 500KB, resumes at end
```

### Test 2: Log File Deleted
```
1. Run agent, create logs
2. Delete log file (keep config)
3. Run agent again
Expected: Creates new log file, starts at 0
```

### Test 3: Circular Buffer Wrap
```
1. Run agent until log reaches 5MB
2. Continue writing (wraps to beginning)
3. Restart agent
Expected: Continues at correct circular position
```

### Test 4: .index File Deleted with Wrapped Log
```
1. Run agent until log reaches 5MB
2. Delete .index file
3. Run agent
Expected: Warns user, starts at 0 (may overwrite)
```

## Diagnostic Output

The validation process produces detailed output:
```
logging.c::validate_and_correct_log_index(156) : Validating LogFileIndex...
logging.c::validate_and_correct_log_index(157) :   Actual file size: 500000
logging.c::validate_and_correct_log_index(158) :   Index from .index file: 0
logging.c::validate_and_correct_log_index(159) :   Index from config: 0
logging.c::validate_and_correct_log_index(193) : WARNING: LogFileIndex is 0 but file has 500000 bytes
logging.c::validate_and_correct_log_index(195) :          Config may have been reset. Resuming at end of file
logging.c::validate_and_correct_log_index(226) : LogFileIndex corrected to 500000
```

## Migration from Old Version

**Breaking Change**: Old config files with `LogFileIndex` field will ignore that value.

Migration steps:
1. On first run, `.index` file will be created (starting at 0)
2. If log file exists, validation will auto-correct to end of file
3. Old `LogFileIndex` in config.json can be safely removed (it's ignored)
4. Future config saves will not include `LogFileIndex`

**Note**: If you have a running system with accurate `LogFileIndex` in config:
1. Manually create `.index` file with that value before upgrading
2. Or accept that logs will resume at end of file (safe for non-wrapped logs)

## Maintenance

### .index File Location
- Same directory as log file
- Same name as log file + `.index` extension
- Can be safely deleted (will be recreated)

### Cleanup
If you want to start fresh:
```bash
rm /var/log/keyfactor-agent.log
rm /var/log/keyfactor-agent.log.index
# Edit config.json and set LogFileIndex to 0
```

## Technical Notes

### Thread Safety
- Not currently thread-safe (single-threaded agent)
- If multi-threading added, need file locking

### Performance Impact
- Minimal: one extra file read on startup
- One extra file write per log flush (already writing config)
- File I/O is buffered

### Disk Space
- `.index` file is tiny (< 20 bytes)
- Negligible impact

## Future Enhancements

Potential improvements:
1. Add timestamp to .index file for staleness detection
2. Add checksum for corruption detection

## Summary

The `.index` file approach provides robust, self-healing log file management that survives configuration resets while maintaining full backwards compatibility. It handles edge cases gracefully and provides clear diagnostic output for troubleshooting.
