# Configuration File

Cancerbero supports configuration files to customize its behavior. This document describes the configuration file format and available options.

## Configuration File Locations

Cancerbero looks for configuration files in this order:

1. **Command-line flag**: `--config PATH`
2. **Environment variable**: `CANCERBERO_CONFIG`
3. **Current directory**: `./cancerbero.yaml`
4. **User config**: `~/.cancerbero/config.yaml`

The first file found is used. If no file is found, default settings are used.

## File Format

Cancerbero supports YAML and JSON configuration files.

### YAML Example

```yaml
# cancerbero.yaml
runtime: /path/to/llama-cli
runtime_version: b8146
format: terminal
verbose: false
full_hash: false
no_color: false
no_interactive: false
```

### JSON Example

```json
{
  "runtime": "/path/to/llama-cli",
  "runtime_version": "b8146",
  "format": "terminal",
  "verbose": false,
  "full_hash": false,
  "no_color": false,
  "no_interactive": false
}
```

## Configuration Options

### Runtime Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `runtime` | string | null | Path to llama.cpp executable |
| `runtime_version` | string | null | Trusted runtime version/build |
| `allow_runtime_exec` | boolean | false | Allow executing runtime with --version |

### Hash Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `full_hash` | boolean | false | Calculate SHA-256 of artifacts |
| `expected_sha256` | string | null | Expected SHA-256 digest |

### Output Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `format` | string | "terminal" | Output format (terminal, json, markdown, md, sarif) |
| `verbose` | boolean | false | Show technical evidence |
| `no_color` | boolean | false | Disable terminal colors |
| `no_banner` | boolean | false | Skip ASCII art banner |
| `no_interactive` | boolean | false | Disable interactive prompts |

### Template Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `template_ref` | string | null | Custom template reference |

### Explain Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `explain` | string | null | Finding ID to explain |

### Batch Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `summary_only` | boolean | false | Show only verdict summary |

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `CANCERBERO_CONFIG` | Path to configuration file | `/etc/cancerbero/config.yaml` |

## Precedence

Configuration values are applied in this order (highest priority first):

1. **Command-line arguments**
2. **Configuration file values**
3. **Default values**

Command-line arguments always override configuration file values.

## Examples

### Basic Configuration

```yaml
# cancerbero.yaml
runtime: /usr/local/bin/llama-cli
runtime_version: b8146
format: terminal
```

### CI/CD Configuration

```yaml
# cancerbero-ci.yaml
runtime: /opt/llama.cpp/llama-cli
runtime_version: b8146
format: json
no_color: true
no_banner: true
no_interactive: true
```

### Development Configuration

```yaml
# cancerbero-dev.yaml
verbose: true
format: terminal
```

### Production Configuration

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

## Using Configuration Files

### Specify Configuration File

```bash
# Use specific config file
cancerbero check ./model.gguf --config ./cancerbero-ci.yaml

# Use environment variable
export CANCERBERO_CONFIG=/etc/cancerbero/config.yaml
cancerbero check ./model.gguf
```

### Override Configuration

```bash
# Config file sets format: terminal
# Command-line overrides to json
cancerbero check ./model.gguf --config ./config.yaml --json report.json
```

### Multiple Configurations

```bash
# Different configs for different environments
cancerbero check ./model.gguf --config ./cancerbero-dev.yaml  # Development
cancerbero check ./model.gguf --config ./cancerbero-ci.yaml   # CI/CD
cancerbero check ./model.gguf --config ./cancerbero-prod.yaml # Production
```

## Configuration Validation

Cancerbero validates configuration values:

- **Unknown keys**: Ignored (with warning in verbose mode)
- **Invalid values**: Error with exit code 3
- **Missing files**: Error with exit code 3

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
cancerbero check ./model.gguf --config ./config-dev.yaml   # Development
cancerbero check ./model.gguf --config ./config-ci.yaml    # CI/CD
cancerbero check ./model.gguf --config ./config-prod.yaml  # Production
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
# See docs/reference/config-file.md for all options

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

## Example Configurations

### Minimal Configuration

```yaml
# Just set the runtime
runtime: /usr/local/bin/llama-cli
```

### Full Configuration

```yaml
# All available options
runtime: /usr/local/bin/llama-cli
runtime_version: b8146
allow_runtime_exec: false
full_hash: false
expected_sha256: null
format: terminal
verbose: false
no_color: false
no_banner: false
no_interactive: false
template_ref: null
explain: null
summary_only: false
```

### CI/CD Configuration

```yaml
# Optimized for CI/CD pipelines
runtime: /opt/llama.cpp/llama-cli
runtime_version: b8146
format: json
no_color: true
no_banner: true
no_interactive: true
```

### Security Audit Configuration

```yaml
# For security audits
runtime: /opt/llama.cpp/llama-cli
runtime_version: b8146
format: sarif
verbose: true
full_hash: true
no_color: true
no_banner: true
no_interactive: true
```
