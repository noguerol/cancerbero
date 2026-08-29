# Exit Codes

Cancerbero uses exit codes to communicate the result of inspections to automation tools, CI/CD pipelines, and scripts.

## Exit Code Summary

| Code | Verdict | Meaning | Pipeline Action |
|------|---------|---------|-----------------|
| `0` | SUITABLE | No blocking conditions found; every core check produced positive evidence | Continue |
| `0` | CLEAN | No suspicious findings on the checks performed (typically: no `--runtime` supplied, so the runtime advisory join was not in scope) | Continue |
| `1` | NOT SUITABLE | Confirmed risk condition found | Block |
| `2` | UNDETERMINED | A check ran and could not complete; a core check was missing beyond the runtime join | Review |
| `3` | ERROR | Invalid input or operational failure | Fail |

## Detailed Explanation

### Exit Code 0: SUITABLE

**When it occurs**:
- All mandatory checks completed successfully
- No suspicious findings detected
- No mandatory unchecked findings
- A runtime advisory join produced positive evidence (the runtime is in scope)

**What it means**:
- The artifact passed all checks Cancerbero performed
- No known vulnerabilities apply to this artifact/runtime combination
- No suspicious patterns detected in templates or companion files

**What it doesn't mean**:
- The model is "safe" or "certified"
- There are no unknown vulnerabilities
- The model behaves correctly in all scenarios

**Example**:
```bash
cancerbero check ./model.gguf --runtime ./llama-cli --runtime-version b8146
echo $?  # 0
```

### Exit Code 0: CLEAN

**When it occurs**:
- The artifact was inspected, no suspicious findings were produced
- A runtime was not supplied, so the runtime advisory join was not in scope
- All in-scope core checks produced positive evidence

**What it means**:
- The artifact passed every check Cancerbero could run without a runtime
- This is a weaker claim than `SUITABLE`; re-run with `--runtime` to upgrade

**Example**:
```bash
cancerbero check ./model.gguf
echo $?  # 0  (CLEAN, not SUITABLE — runtime join was not in scope)
```

### Exit Code 1: NOT SUITABLE

**When it occurs**:
- At least one finding has status `suspicious`
- The finding is mandatory (affects the verdict)

**What it means**:
- A confirmed risk condition was found
- The artifact or runtime has a known issue
- Action is required before deployment

**Common causes**:
- Known CVE affects the runtime
- Poisoned template pattern detected
- Malicious companion file instruction
- Template mismatch across GGUF files

**Example**:
```bash
cancerbero check ./model.gguf --runtime ./llama-cli --runtime-version b5000
echo $?  # 1 (if CVE affects build 5000)
```

### Exit Code 2: UNDETERMINED

**When it occurs**:
- At least one mandatory finding has status `unchecked` or `error`
- No suspicious findings detected
- AND at least one non-runtime core check was missing (otherwise the verdict downgrades to `CLEAN`)

**What it means**:
- Required evidence was missing
- A check couldn't be completed
- The verdict cannot be determined

**Common causes**:
- Runtime build unknown (when a runtime IS supplied)
- No expected digest provided
- Knowledge bundle expired
- GGUF parsing error

**Example**:
```bash
cancerbero check ./model.gguf --runtime ./llama-cli
echo $?  # 2 (if runtime build unknown)
```

### Exit Code 3: ERROR

**When it occurs**:
- Invalid command-line arguments
- Operational failure (file not found, permission denied)
- Internal error

**What it means**:
- Cancerbero itself encountered an error
- The inspection could not be performed
- Check the error message for details

**Common causes**:
- Invalid command-line arguments
- File not found
- Permission denied
- Configuration error

**Example**:
```bash
cancerbero check ./nonexistent.gguf
echo $?  # 3
```

## Exit Code Logic

```
IF any finding is SUSPICIOUS and the severity × classification matrix blocks
  THEN exit_code = 1 (NOT SUITABLE)

ELSE IF any finding is (UNCHECKED or ERROR) and MANDATORY
   OR a non-runtime core check is missing
  THEN exit_code = 2 (UNDETERMINED)

ELSE IF runtime advisory join was not in scope (no runtime supplied)
  THEN exit_code = 0 (CLEAN)

ELSE
  THEN exit_code = 0 (SUITABLE)
```

**Note**: Exit code 3 is reserved for Cancerbero's own errors, not finding-based.

## Using Exit Codes in Scripts

### Bash

```bash
#!/bin/bash

cancerbero check ./model.gguf --no-interactive
EXIT_CODE=$?

case $EXIT_CODE in
  0)
    echo "Model is suitable for deployment"
    ;;
  1)
    echo "Model has security issues - do not deploy"
    exit 1
    ;;
  2)
    echo "Model check incomplete - review required"
    exit 1
    ;;
  3)
    echo "Cancerbero error - check logs"
    exit 1
    ;;
esac
```

### Python

```python
import subprocess
import sys

result = subprocess.run(
    ["cancerbero", "check", "./model.gguf", "--no-interactive"],
    capture_output=True,
    text=True
)

if result.returncode == 0:
    print("Model is suitable for deployment")
elif result.returncode == 1:
    print("Model has security issues - do not deploy")
    sys.exit(1)
elif result.returncode == 2:
    print("Model check incomplete - review required")
    sys.exit(1)
else:
    print(f"Cancerbero error: {result.stderr}")
    sys.exit(1)
```

### GitHub Actions

```yaml
- name: Check model
  id: check
  run: cancerbero check ./model.gguf --no-interactive
  continue-on-error: true

- name: Gate on findings
  if: steps.check.outcome == 'failure'
  run: |
    echo "Model security check failed with exit code ${{ steps.check.outcome }}"
    exit 1
```

## Exit Code vs. Verdict

The exit code is a summary of the verdict for automation. The full report contains more detail:

| Exit Code | Verdict | Report Contains |
|-----------|---------|-----------------|
| `0` | SUITABLE | All findings (including informational) |
| `0` | CLEAN | Findings from the checks performed; runtime join explicitly skipped |
| `1` | NOT SUITABLE | Suspicious findings with actions |
| `2` | UNDETERMINED | Unchecked findings with reasons |
| `3` | ERROR | Error messages |

**Always check the full report**, not just the exit code, for complete information.

## Customizing Exit Code Behavior

Currently, Cancerbero's exit code behavior is fixed. Future versions may support:

- Custom exit code policies
- Severity-based exit codes
- Configurable thresholds

## Troubleshooting

### Issue: Exit code 2 when I expect 0

**Cause**: A mandatory check couldn't be completed.

**Solution**: 
1. Check the "Not Checked" section in the report
2. Provide missing information (runtime version, expected digest)
3. Update Cancerbero if bundle is expired

### Issue: Exit code 1 but I don't see findings

**Cause**: Findings may be in verbose mode only.

**Solution**: Run with `--verbose` to see all findings.

### Issue: Exit code 3 with no error message

**Cause**: Internal error or invalid arguments.

**Solution**: Check stderr for error messages, verify command syntax.

## Best Practices

### 1. Always Check Exit Codes in Automation

```bash
# ✅ Correct
cancerbero check ./model.gguf --no-interactive || exit 1

# ❌ Wrong - ignores exit code
cancerbero check ./model.gguf --no-interactive
```

### 2. Use Appropriate Exit Code Handling

```bash
# For CI/CD - fail on any issue
cancerbero check ./model.gguf --no-interactive || exit 1

# For monitoring - log but continue
cancerbero check ./model.gguf --no-interactive
EXIT_CODE=$?
log_result $EXIT_CODE
```

### 3. Combine with Report Generation

```bash
# Generate report and check exit code
cancerbero check ./model.gguf --no-interactive --json report.json
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "See report.json for details"
    exit $EXIT_CODE
fi
```

### 4. Use Summary Mode for Quick Checks

```bash
# Quick check with summary
cancerbero check ./model.gguf --summary-only --no-interactive
EXIT_CODE=$?

# Full report only if issues found
if [ $EXIT_CODE -ne 0 ]; then
    cancerbero check ./model.gguf --verbose
fi
```
