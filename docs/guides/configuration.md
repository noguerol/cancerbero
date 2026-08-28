# Configuration Guide

This guide explains how to configure Cancerbero for different use cases and environments.

## Quick Configuration

### Minimal Configuration

Create `cancerbero.yaml` in your project root:

```yaml
runtime: /usr/local/bin/llama-cli
runtime_version: b8146
```

### CI/CD Configuration

Create `cancerbero-ci.yaml`:

```yaml
runtime: /opt/llama.cpp/llama-cli
runtime_version: b8146
format: json
no_color: true
no_banner: true
no_interactive: true
```

### Development Configuration

Create `cancerbero-dev.yaml`:

```yaml
verbose: true
format: terminal
```

## Configuration Options

### Runtime Configuration

```yaml
# Path to llama.cpp executable
runtime: /usr/local/bin/llama-cli

# Trusted runtime version/build
runtime_version: b8146

# Allow executing runtime with --version (opt-in)
allow_runtime_exec: false
```

### Hash Configuration

```yaml
# Calculate SHA-256 of artifacts
full_hash: false

# Expected SHA-256 digest (for verification)
expected_sha256: null
```

### Output Configuration

```yaml
# Output format: terminal, json, markdown, md, sarif
format: terminal

# Show technical evidence
verbose: false

# Disable terminal colors
no_color: false

# Skip ASCII art banner
no_banner: false

# Disable interactive prompts
no_interactive: false
```

### Template Configuration

```yaml
# Custom template reference
template_ref: null
```

### Explain Configuration

```yaml
# Finding ID to explain
explain: null
```

### Batch Configuration

```yaml
# Show only verdict summary
summary_only: false
```

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `CANCERBERO_CONFIG` | Path to configuration file | `/etc/cancerbero/config.yaml` |

## Precedence

Configuration values are applied in this order (highest priority first):

1. **Command-line arguments**
2. **Configuration file values**
3. **Default values**

### Example

```yaml
# cancerbero.yaml
format: terminal
verbose: false
```

```bash
# Command-line overrides config file
cancerbero check ./model.gguf --format json --verbose
# Result: format=json, verbose=true
```

## Use Cases

### Development

```yaml
# cancerbero-dev.yaml
verbose: true
format: terminal
no_color: false
no_banner: false
no_interactive: false
```

### CI/CD

```yaml
# cancerbero-ci.yaml
format: json
no_color: true
no_banner: true
no_interactive: true
```

### Production

```yaml
# cancerbero-prod.yaml
runtime: /opt/llama.cpp/llama-cli
runtime_version: b8146
format: sarif
no_color: true
no_banner: true
no_interactive: true
full_hash: true
```

### Security Audit

```yaml
# cancerbero-audit.yaml
runtime: /opt/llama.cpp/llama-cli
runtime_version: b8146
format: json
verbose: true
full_hash: true
no_color: true
no_banner: true
no_interactive: true
```

### Batch Processing

```yaml
# cancerbero-batch.yaml
format: json
no_color: true
no_banner: true
no_interactive: true
summary_only: false
```

## Configuration File Locations

Cancerbero looks for configuration files in this order:

1. **Command-line flag**: `--config PATH`
2. **Environment variable**: `CANCERBERO_CONFIG`
3. **Current directory**: `./cancerbero.yaml`
4. **User config**: `~/.cancerbero/config.yaml`

### Using Different Locations

```bash
# Use specific config file
cancerbero check ./model.gguf --config ./cancerbero-ci.yaml

# Use environment variable
export CANCERBERO_CONFIG=/etc/cancerbero/config.yaml
cancerbero check ./model.gguf

# Use current directory config
cancerbero check ./model.gguf  # Uses ./cancerbero.yaml if exists

# Use user config
cancerbero check ./model.gguf  # Uses ~/.cancerbero/config.yaml if exists
```

## Configuration Examples

### Example 1: Basic Project

```yaml
# cancerbero.yaml
runtime: /usr/local/bin/llama-cli
runtime_version: b8146
format: terminal
```

### Example 2: Multi-Environment

```yaml
# cancerbero-dev.yaml
verbose: true
format: terminal

# cancerbero-ci.yaml
format: json
no_color: true
no_banner: true
no_interactive: true

# cancerbero-prod.yaml
format: sarif
no_color: true
no_banner: true
no_interactive: true
full_hash: true
```

### Example 3: Team Configuration

```yaml
# cancerbero.yaml (shared via version control)
runtime: /opt/llama.cpp/llama-cli
runtime_version: b8146
format: terminal
verbose: false
no_color: false
no_banner: false
no_interactive: false
```

### Example 4: CI/CD Pipeline

```yaml
# .github/cancerbero.yaml
format: json
no_color: true
no_banner: true
no_interactive: true
```

```yaml
# GitHub Actions
- name: Check models
  run: cancerbero check ./models/ --config .github/cancerbero.yaml --json report.json
```

## Best Practices

### 1. Use Configuration Files for Consistency

```yaml
# cancerbero.yaml - shared across team
runtime: /opt/llama.cpp/llama-cli
runtime_version: b8146
format: terminal
verbose: false
```

### 2. Use Environment-Specific Configs

```bash
# Different configs for different environments
cancerbero check ./model.gguf --config ./cancerbero-dev.yaml   # Development
cancerbero check ./model.gguf --config ./cancerbero-ci.yaml    # CI/CD
cancerbero check ./model.gguf --config ./cancerbero-prod.yaml  # Production
```

### 3. Keep Sensitive Values Out of Config

```yaml
# ✅ Good - runtime path in config
runtime: /opt/llama.cpp/llama-cli

# ❌ Bad - sensitive values in config
expected_sha256: abc123...  # Use command-line instead
```

### 4. Version Control Configuration

```bash
# Add config to version control
git add cancerbero.yaml

# But not environment-specific configs
echo "cancerbero-local.yaml" >> .gitignore
```

### 5. Document Configuration

```yaml
# cancerbero.yaml
# Cancerbero configuration for project X
# See docs/guides/configuration.md for all options

runtime: /opt/llama.cpp/llama-cli  # Production llama.cpp
runtime_version: b8146              # Latest stable build
format: terminal                    # Human-readable output
verbose: false                      # Don't show technical details
```

## Troubleshooting

### Issue: Configuration not loaded

**Cause**: File not found or invalid format.

**Solution**: 
1. Check file path
2. Verify YAML/JSON syntax
3. Use `--config` to specify exact path

### Issue: Values not applied

**Cause**: Command-line arguments override config.

**Solution**: Check command-line arguments, remove overrides.

### Issue: Unknown keys warning

**Cause**: Configuration file has unknown keys.

**Solution**: Check spelling, remove unknown keys.

## Advanced Configuration

### Custom Template References

```yaml
# Use custom template reference
template_ref: llama3-instruct
```

### Explain Mode

```yaml
# Explain specific finding
explain: cbr.gguf.inspection_error
```

### Summary Mode

```yaml
# Show only verdict summary
summary_only: true
```

## Configuration Validation

Cancerbero validates configuration values:

- **Unknown keys**: Ignored (with warning in verbose mode)
- **Invalid values**: Error with exit code 3
- **Missing files**: Error with exit code 3

## Migration Guide

### From Command-Line to Configuration

```bash
# Before: all command-line
cancerbero check ./model.gguf --runtime ./llama-cli --runtime-version b8146 --format json --no-interactive

# After: configuration file
# cancerbero.yaml
runtime: ./llama-cli
runtime_version: b8146
format: json
no_interactive: true
```

```bash
# Simple command
cancerbero check ./model.gguf
```

### From Environment Variables to Configuration

```bash
# Before: environment variables
export CANCERBERO_RUNTIME=./llama-cli
export CANCERBERO_VERSION=b8146

# After: configuration file
# cancerbero.yaml
runtime: ./llama-cli
runtime_version: b8146
```

## Reference

See [Configuration File Reference](../reference/config-file.md) for complete documentation of all options.
