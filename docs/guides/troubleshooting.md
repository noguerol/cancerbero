# Troubleshooting Guide

This guide helps you resolve common issues with Cancerbero.

## Installation Issues

### Issue: `pip install cancerbero` fails

**Symptoms**:
```
ERROR: Could not find a version that satisfies the requirement cancerbero
```

**Causes**:
- Cancerbero not yet published to PyPI
- Python version too old
- Network issues

**Solutions**:
1. Install from source:
   ```bash
   git clone https://github.com/noguerol/cancerbero.git
   cd cancerbero
   pip install -e .
   ```

2. Check Python version:
   ```bash
   python --version  # Should be 3.10+
   ```

3. Use uv:
   ```bash
   uv pip install cancerbero
   ```

### Issue: `ModuleNotFoundError: No module named 'jinja2'`

**Symptoms**:
```
ModuleNotFoundError: No module named 'jinja2'
```

**Cause**: Jinja2 dependency not installed.

**Solution**:
```bash
pip install jinja2
# Or reinstall cancerbero
pip install -e .
```

### Issue: Permission denied during installation

**Symptoms**:
```
PermissionError: [Errno 13] Permission denied
```

**Cause**: Installing to system Python without permissions.

**Solutions**:
1. Use `--user` flag:
   ```bash
   pip install --user cancerbero
   ```

2. Use virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install cancerbero
   ```

3. Use uv:
   ```bash
   uv pip install cancerbero
   ```

## Runtime Issues

### Issue: `cancerbero: command not found`

**Symptoms**:
```
bash: cancerbero: command not found
```

**Cause**: Cancerbero not in PATH.

**Solutions**1. Check installation:
   ```bash
   pip show cancerbero
   ```

2. Add to PATH:
   ```bash
   export PATH="$HOME/.local/bin:$PATH"
   ```

3. Use full path:
   ```bash
   python -m cancerbero check ./model.gguf
   ```

### Issue: `cancerbero: error: unrecognized arguments`

**Symptoms**:
```
cancerbero: error: unrecognized arguments: --no-banner
```

**Cause**: Flag on wrong command level.

**Solution**: Check flag placement:
```bash
# ✅ Correct - global flags before command
cancerbero --no-banner check ./model.gguf

# ❌ Wrong - global flags after command
cancerbero check ./model.gguf --no-banner
```

### Issue: `cancerbero: error: --runtime-version requires --runtime`

**Symptoms**:
```
cancerbero: error: --runtime-version requires --runtime
```

**Cause**: `--runtime-version` without `--runtime`.

**Solution**:
```bash
# ✅ Correct
cancerbero check ./model.gguf --runtime ./llama-cli --runtime-version b8146

# ❌ Wrong
cancerbero check ./model.gguf --runtime-version b8146
```

## Inspection Issues

### Issue: GGUF parsing fails

**Symptoms**:
```
✖  ERRORS
  ✖ GGUF inspection failed: Invalid GGUF magic
```

**Causes**:
- File is not a GGUF file
- File is corrupted
- File is truncated

**Solutions**:
1. Verify file is actually GGUF:
   ```bash
   file model.gguf
   # Should show: data
   head -c 4 model.gguf | xxd
   # Should show: 47 47 55 46 (GGUF)
   ```

2. Re-download the file

3. Check file integrity:
   ```bash
   sha256sum model.gguf
   ```

### Issue: Runtime build unknown

**Symptoms**:
```
?  NOT CHECKED
  - Runtime build could not be identified from static evidence.
```

**Cause**: Cancerbero can't determine llama.cpp version.

**Solutions**1. Provide version explicitly:
   ```bash
   cancerbero check ./model.gguf --runtime ./llama-cli --runtime-version b8146
   ```

2. Allow execution (opt-in):
   ```bash
   cancerbero check ./model.gguf --runtime ./llama-cli --allow-runtime-exec
   ```

3. Check build files exist:
   ```bash
   ls -la ./build-info.json ./build-info.txt
   ```

### Issue: Template analysis fails

**Symptoms**:
```
✖  ERRORS
  ✖ Template exceeds the 1048576-byte analysis limit.
```

**Cause**: Chat template is very large.

**Solution**: This is a safety limit. Large templates may indicate:
- Legitimate complex template (rare)
- Malicious template with embedded payload

Investigate the template manually.

### Issue: Knowledge bundle expired

**Symptoms**:
```
ℹ  NOTES
  - The embedded knowledge bundle has expired; advisory coverage is undetermined.
```

**Cause**: Cancerbero version is old.

**Solution**: Update Cancerbero:
```bash
pip install --upgrade cancerbero
# Or from source
git pull
pip install -e .
```

## Output Issues

### Issue: No color in terminal

**Symptoms**: Output has no colors.

**Causes**:
- `--no-color` flag set
- Terminal doesn't support colors
- Output is piped

**Solutions**:
1. Check if colors are supported:
   ```bash
   echo -e "\033[32mGreen\033[0m"
   ```

2. Remove `--no-color` flag

3. Use terminal that supports colors

### Issue: Interactive prompt doesn't appear

**Symptoms**: No prompt after inspection.

**Causes**:
- `--no-interactive` flag set
- Output is piped
- `--json` or `--format` specified
- `--summary-only` specified

**Solution**: These are expected behaviors. The prompt only appears in interactive terminal sessions without format flags.

### Issue: JSON output is empty

**Symptoms**: Empty JSON file.

**Cause**: Cancerbero error before generating output.

**Solution**: Check stderr for error messages:
```bash
cancerbero check ./model.gguf --json report.json 2>error.log
cat error.log
```

## Performance Issues

### Issue: Inspection is slow

**Symptoms**: Inspection takes > 10 seconds.

**Causes**:
- Very large GGUF file (> 50GB)
- Slow filesystem
- Hash calculation enabled

**Solutions**:
1. Disable hash calculation:
   ```bash
   cancerbero check ./model.gguf  # Without --full
   ```

2. Use faster storage

3. Check file size:
   ```bash
   ls -lh model.gguf
   ```

### Issue: High memory usage

**Symptoms**: Cancerbero uses > 1GB RAM.

**Cause**: Very large metadata or many companion files.

**Solution**: This is unusual. Report as a bug if it occurs with normal files.

## CI/CD Issues

### Issue: Pipeline hangs

**Symptoms**: Pipeline never completes.

**Cause**: Cancerbero waiting for interactive input.

**Solution**: Always use `--no-interactive` in CI/CD:
```bash
cancerbero check ./model.gguf --no-interactive
```

### Issue: Exit code not captured

**Symptoms**: Pipeline doesn't fail on issues.

**Cause**: Exit code not checked.

**Solution**:
```bash
cancerbero check ./model.gguf --no-interactive
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    exit $EXIT_CODE
fi
```

### Issue: Report not generated

**Symptoms**: No report file after inspection.

**Cause**: Cancerbero failed before generating report.

**Solution**: Check stderr and exit code:
```bash
cancerbero check ./model.gguf --json report.json 2>error.log
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo "Error: $(cat error.log)"
    exit $EXIT_CODE
fi
```

## False Positives

### Issue: Legitimate template flagged as suspicious

**Symptoms**:
```
⚠  FINDINGS
  [HIGH] Template contains conditional logic...
```

**Cause**: Template has legitimate conditional logic.

**Solution**: This is expected for complex templates. Cancerbero flags patterns that could be malicious, but many legitimate templates use similar patterns. Review the finding and determine if it's acceptable for your use case.

### Issue: Companion file flagged as suspicious

**Symptoms**:
```
⚠  FINDINGS
  [HIGH] File contains direct prompt injection...
```

**Cause**: Companion file has instructions that match attack patterns.

**Solution**: Review the file. If it's legitimate, the finding is informational. Cancerbero flags patterns that could be malicious, but some legitimate files may match.

## Getting Help

### Check Documentation

1. [Installation Guide](installation.md)
2. [Quick Start](quickstart.md)
3. [CLI Reference](../reference/cli.md)
4. [Understanding Reports](reports.md)

### Report Issues

If you encounter a bug or unexpected behavior:

1. Check existing issues: [GitHub Issues](https://github.com/noguerol/cancerbero/issues)
2. Create new issue with:
   - Cancerbero version (`cancerbero --version`)
   - Python version (`python --version`)
   - Operating system
   - Command that failed
   - Error message
   - Expected behavior
   - Actual behavior

### Community Support

- GitHub Discussions
- Issue Tracker
- Security Advisories

## Debugging

### Enable Verbose Output

```bash
cancerbero check ./model.gguf --verbose
```

This shows:
- All findings (including informational)
- Technical evidence
- Detection details

### Check Configuration

```bash
# Show effective configuration
cancerbero check ./model.gguf --verbose 2>&1 | head -20
```

### Test with Known Good File

```bash
# Test with a known good GGUF file
cancerbero check ./known-good.gguf --verbose
```

### Check File Integrity

```bash
# Verify GGUF magic
head -c 4 model.gguf | xxd

# Check file size
ls -lh model.gguf

# Calculate hash
sha256sum model.gguf
```
