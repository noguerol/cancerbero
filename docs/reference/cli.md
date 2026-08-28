# CLI Reference

Complete command-line interface documentation for Cancerbero.

## Global Options

These options apply to all commands:

```bash
cancerbero [global-options] COMMAND [command-options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--version` | Show version and exit | |
| `--config PATH` | Path to configuration file | Auto-detect |
| `--no-color` | Disable terminal colors and animations | `false` |
| `--no-banner` | Skip the ASCII art banner | `false` |
| `--no-interactive` | Disable interactive prompts (for CI/CD) | `false` |
| `-h, --help` | Show help message | |

## Commands

### `check`

Inspect GGUF artifacts and llama.cpp runtimes without loading models.

```bash
cancerbero check TARGET [TARGET ...] [options]
```

#### Arguments

| Argument | Description | Required |
|----------|-------------|----------|
| `TARGET` | One or more paths to GGUF files, llama.cpp binaries, or directories | Yes |

#### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--runtime PATH` | Explicit llama.cpp executable or directory | Auto-detect |
| `--runtime-version VALUE` | Trusted runtime version/build override (e.g., `b8146`) | Auto-detect |
| `--full` | Stream each artifact to calculate complete SHA-256 | `false` |
| `--expected-sha256 HEX` | Trusted expected SHA-256 (implies `--full`) | |
| `--allow-runtime-exec` | Opt-in: run runtime with `--version` in constrained subprocess | `false` |
| `--format FORMAT` | Output format: `terminal`, `json`, `markdown`, `md`, `sarif` | `terminal` |
| `--json PATH\|-` | Write canonical JSON (implies `--format json`) | |
| `--include-observations` | Include non-deterministic timings in JSON | `false` |
| `--verbose` | Show technical evidence and notes | `false` |
| `--explain FINDING_ID` | Show detailed explanation for a specific finding | |
| `--summary-only` | Show only the verdict summary | `false` |

#### Examples

```bash
# Basic inspection
cancerbero check ./model.gguf

# With runtime
cancerbero check ./model.gguf --runtime ./llama-cli --runtime-version b8146

# Directory scan
cancerbero check ./models/

# Hash verification
cancerbero check ./model.gguf --full --expected-sha256 abc123...

# JSON output
cancerbero check ./model.gguf --json report.json

# Markdown output
cancerbero check ./model.gguf --format markdown > report.md

# SARIF for GitHub
cancerbero check ./model.gguf --format sarif > results.sarif

# Verbose mode
cancerbero check ./model.gguf --verbose

# Explain a finding
cancerbero check ./model.gguf --explain cbr.gguf.inspection_error

# Quick summary
cancerbero check ./model.gguf --summary-only

# CI/CD mode
cancerbero check ./model.gguf --no-interactive --no-banner --no-color
```

## Output Formats

### Terminal (default)

Human-readable output with colors, icons, and structured sections.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Cancerbero — SUITABLE
  No blocking conditions found within the checks performed.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TARGETS
  Artifact : Qwen3.6-27B  (GGUF v3, qwen35, 866 tensors)
  File     : ./model.gguf
  Template : present (8057 chars)
  Bundle   : 2026.08.28  (digest 2dd03f72d12d6d59…, canonical_sha256_verified)

COVERAGE
  1 clean · 4 unchecked

  This is a suitability assessment, not a safety certification.
  Absence of findings does not prove the artifact is safe.
```

### JSON

Deterministic, machine-readable output for automation.

```json
{
  "schema_version": "1.0",
  "cancerbero_version": "0.1.0",
  "command": ["cancerbero", "check", "./model.gguf"],
  "verdict": "suitable",
  "exit_code": 0,
  "artifacts": [...],
  "runtimes": [...],
  "findings": [...],
  "coverage": {...},
  "bundle": {...}
}
```

### Markdown

Shareable reports for documentation and PRs.

```markdown
# Cancerbero Audit Report

**Verdict:** SUITABLE
**Version:** 0.1.0

## Targets

### Artifacts

| Name | Architecture | Version | Tensors | Template |
|------|--------------|---------|---------|----------|
| Qwen3.6-27B | qwen35 | GGUF v3 | 866 | present |

## Coverage

1 clean · 4 unchecked
```

### SARIF

Static Analysis Results Interchange Format for GitHub Code Scanning.

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Cancerbero",
        "version": "0.1.0"
      }
    },
    "results": [...]
  }]
}
```

## Exit Codes

| Code | Verdict | Meaning |
|------|---------|---------|
| `0` | SUITABLE | No blocking conditions found |
| `1` | NOT SUITABLE | Confirmed risk condition found |
| `2` | UNDETERMINED | Required evidence missing |
| `3` | ERROR | Invalid input or operational failure |

## Configuration File

Cancerbero reads configuration from:

1. `./cancerbero.yaml` (current directory)
2. `~/.cancerbero/config.yaml` (user config)
3. Path specified by `--config` flag
4. Path specified by `CANCERBERO_CONFIG` environment variable

### Example Configuration

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

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CANCERBERO_CONFIG` | Path to configuration file |

## Interactive Mode

When running in a terminal (TTY), Cancerbero offers an interactive prompt after displaying results:

```
  ? Export to another format?
    1. JSON (machine-readable)
    2. Markdown (documentation)
    3. SARIF (GitHub Code Scanning)
    0. Skip
```

This prompt is disabled when:
- `--no-interactive` flag is set
- Output is piped (not a TTY)
- `--json` or `--format` is specified
- `--summary-only` is specified

## Progress Feedback

Cancerbero shows progress during inspection:

```
  ▸ Checking 1 target(s)...
  ✓ Knowledge bundle 2026.08.28 loaded
  ℹ Found 1 GGUF artifact(s) to inspect
  ✓ Inspected: model.gguf
  ℹ Chat template analyzed
  ℹ Checked against 7 advisory rule(s)
```

Progress is disabled when:
- `--no-color` flag is set
- Output is not a TTY

## Banner

Cancerbero displays an ASCII art banner on startup:

```
   ██████╗ █████╗ ███╗   ██╗ ██████╗███████╗██████╗ ██████╗ ███████╗██████╗  ██████╗
  ██╔════╝██╔══██╗████╗  ██║██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔═══██╗
  ██║     ███████║██╔██╗ ██║██║     █████╗  ██████╔╝██████╔╝█████╗  ██████╔╝██║   ██║
  ██║     ██╔══██║██║╚██╗██║██║     ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██╗██║   ██║
  ╚██████╗██║  ██║██║ ╚████║╚██████╗███████╗██║  ██║██████╔╝███████╗██║  ██║╚██████╔╝
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝

  0.1.0 — Local GGUF & llama.cpp inspector
```

The banner is disabled when:
- `--no-banner` flag is set
- `--no-color` flag is set
- Output is not a TTY
