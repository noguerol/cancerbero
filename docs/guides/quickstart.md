# Quick Start Guide

Get started with Cancerbero in minutes.

## Installation

```bash
# Install from source
git clone https://github.com/cancerbero-security/cancerbero.git
cd cancerbero
pip install -e .

# Or with uv
uv pip install cancerbero
```

## Your First Check

### Basic Check

```bash
# Check a GGUF file
cancerbero check ./model.gguf
```

**Important:** Without a runtime, the verdict will be `UNDETERMINED` because the `runtime_advisory_join` core check is missing. This is by design — Cancerbero requires positive evidence from core checks before producing a `SUITABLE` verdict.

### Check with Runtime (Recommended)

```bash
# Provide runtime for SUITABLE verdict
cancerbero check ./model.gguf --runtime ./llama-cli --runtime-version b8146
```

This allows Cancerbero to perform the advisory join and produce a definitive verdict.

### Check a Directory

```bash
# Check all models in a directory
cancerbero check ./models/
```

## Understanding the Output

### Terminal Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Cancerbero — SUITABLE
  No blocking conditions found within the checks performed.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TARGETS
  Artifact : MyModel  (GGUF v3, llama, 100 tensors)
  File     : ./model.gguf
  Template : present (5000 chars)
  Bundle   : 2026.08.28.1  (digest bf844af458f21184…, canonical_sha256_verified)

COVERAGE
  3 clean · 4 unchecked

  This is a suitability assessment, not a safety certification.
  Absence of findings does not prove the artifact is safe.
```

### Verdict Meanings

| Verdict | Meaning | Action |
|---------|---------|--------|
| **SUITABLE** | No blocking conditions found | Safe to proceed |
| **NOT SUITABLE** | Confirmed risk condition found | Do not load |
| **UNDETERMINED** | Required evidence missing | Review findings |

### Exit Codes

| Code | Meaning | Use in Scripts |
|------|---------|----------------|
| `0` | SUITABLE | `cancerbero check ... && echo "OK"` |
| `1` | NOT SUITABLE | `cancerbero check ... \|\| echo "BLOCKED"` |
| `2` | UNDETERMINED | `cancerbero check ...; echo "REVIEW"` |
| `3` | ERROR | `cancerbero check ...; echo "ERROR"` |

## Common Use Cases

### Verify Model Integrity

```bash
# Calculate and verify SHA-256 digest
cancerbero check ./model.gguf --full --expected-sha256 abc123...
```

### Generate Reports

```bash
# JSON report for automation
cancerbero check ./model.gguf --json report.json

# Markdown report for documentation
cancerbero check ./model.gguf --format markdown > report.md

# SARIF report for GitHub Code Scanning
cancerbero check ./model.gguf --format sarif > results.sarif
```

### CI/CD Integration

```bash
# Non-interactive mode for CI/CD
cancerbero check ./model.gguf --no-interactive --no-banner --no-color

# Gate deployment
cancerbero check ./model.gguf --no-interactive || exit 1
```

### Verbose Mode

```bash
# Show detailed analysis
cancerbero check ./model.gguf --verbose

# Explain a specific finding
cancerbero check ./model.gguf --explain cbr.gguf.inspection_error
```

## What Cancerbero Checks

### Structure
GGUF v2/v3 header, metadata types, tensor descriptors, alignment, offsets.

### Template Security
Static Jinja AST analysis with enhanced security patterns:
- Poisoned GGUF Templates (Pillar Security)
- Dangerous functions (os.system, subprocess, eval, exec)
- Encoded payloads (Base64, Unicode, HTML entities)
- Data exfiltration patterns

### Companion Files
Inspects config.json, tokenizer_config.json, Modelfile, manifests, adapters, and .py files:
- Pickle deserialization risks
- MCP server configurations
- Hardcoded credentials
- Remote code execution configurations
- Network exfiltration patterns

### Runtime
Identifies llama.cpp from nearby build files, git metadata, or explicit override.

### Advisory Join
Crosses artifact properties with runtime build against versioned CVE knowledge.

## Next Steps

- [Configuration](configuration.md) — Customize Cancerbero for your workflow
- [Understanding Reports](reports.md) — Deep dive into report interpretation
- [CI/CD Integration](cicd.md) — Automate checks in your pipeline
- [Security Documentation](../security/index.md) — Understand what Cancerbero detects
