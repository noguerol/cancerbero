# Output Formats

Cancerbero supports multiple output formats for different use cases. This document describes each format in detail.

## Terminal (Default)

The terminal format is designed for human readability in interactive sessions.

### Features

- **Colors**: ANSI colors for different finding types
- **Icons**: Visual indicators (✓, ✗, ⚠, ❓, ➖)
- **Structure**: Clear sections with headers
- **Progress**: Real-time feedback during inspection
- **Banner**: ASCII art with version

### Example Output

```
   ██████╗ █████╗ ███╗   ██╗ ██████╗███████╗██████╗ ██████╗ ███████╗██████╗  ██████╗
  ██╔════╝██╔══██╗████╗  ██║██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔═══██╗
  ██║     ███████║██╔██╗ ██║██║     █████╗  ██████╔╝██████╔╝█████╗  ██████╔╝██║   ██║
  ██║     ██╔══██║██║╚██╗██║██║     ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██╗██║   ██║
  ╚██████╗██║  ██║██║ ╚████║╚██████╗███████╗██║  ██║██████╔╝███████╗██║  ██║╚██████╔╝
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝

  0.1.0 — Local GGUF & llama.cpp inspector
  ▸ Checking 1 target(s)...
  ✓ Knowledge bundle 2026.08.28 loaded
  ℹ Found 1 GGUF artifact(s) to inspect
  ✓ Inspected: model.gguf
  ℹ Chat template analyzed
  ℹ Analyzed 1 artifact(s)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Cancerbero — SUITABLE
  No blocking conditions found within the checks performed.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TARGETS
  Artifact : Qwen3.6-27B  (GGUF v3, qwen35, 866 tensors, type=30, quant_v2)
  File     : ./model.gguf
  Template : present (8057 chars)
  Bundle   : 2026.08.28  (digest 2dd03f72d12d6d59…, canonical_sha256_verified)

COVERAGE
  1 clean · 4 unchecked

  This is a suitability assessment, not a safety certification.
  Absence of findings does not prove the artifact is safe.
```

### When to Use

- Interactive terminal sessions
- Manual model review
- Debugging and exploration
- Presentations and demos

### Flags

| Flag | Effect |
|------|--------|
| `--no-color` | Disable ANSI colors |
| `--no-banner` | Skip ASCII art banner |
| `--verbose` | Show technical evidence |
| `--summary-only` | Show only verdict line |

## JSON

The JSON format provides deterministic, machine-readable output for automation.

### Features

- **Deterministic**: Same input → same output (excluding observations)
- **Sorted keys**: Consistent key ordering
- **Versioned schema**: Schema version included
- **Complete**: All finding details and evidence

### Schema

```json
{
  "schema_version": "1.0",
  "cancerbero_version": "0.1.0",
  "command": ["cancerbero", "check", "./model.gguf"],
  "targets": [...],
  "artifacts": [...],
  "runtimes": [...],
  "findings": [...],
  "bundle": {...},
  "verdict": "suitable",
  "exit_code": 0,
  "options": {...},
  "coverage": {...},
  "limitations": [...]
}
```

### Finding Structure

```json
{
  "id": "cbr.gguf.inspection_error",
  "head": "loading",
  "check": "gguf_structure",
  "status": "error",
  "severity": "info",
  "confidence": "high",
  "summary": "GGUF inspection failed: ...",
  "evidence": {
    "artifact": "/path/to/model.gguf",
    "error": "...",
    "explanation": "...",
    "origin": "..."
  },
  "action": null,
  "references": [],
  "mandatory": true
}
```

### When to Use

- CI/CD pipelines
- Automated processing
- Integration with other tools
- Audit trails
- Programmatic analysis

### Flags

| Flag | Effect |
|------|--------|
| `--json PATH` | Write to file |
| `--json -` | Write to stdout |
| `--include-observations` | Include timings |

## Markdown

The Markdown format generates shareable reports for documentation.

### Features

- **Structured**: Headers, tables, lists
- **Readable**: Clean formatting
- **Shareable**: Works in GitHub, GitLab, documentation
- **Complete**: All sections included

### Example Output

```markdown
# Cancerbero Audit Report

**Verdict:** SUITABLE
**Version:** 0.1.0
**Schema:** 1.0

> **Note:** This is a suitability assessment for the checks performed,
> not a safety certification. Absence of findings does not prove the
> artifact is safe.

## Targets

### Artifacts

| Name | Architecture | Version | Tensors | Template |
|------|--------------|---------|---------|----------|
| Qwen3.6-27B | qwen35 | GGUF v3 | 866 | present |

## Coverage

1 clean · 4 unchecked

## Knowledge Bundle

- **Version:** 2026.08.28
- **Digest:** `2dd03f72d12d6d59…`
- **Integrity:** canonical_sha256_verified
- **Expires:** 2027-08-28T00:00:00Z

## Reproduction

```bash
cancerbero check ./model.gguf --format markdown
```
```

### When to Use

- Pull requests
- Documentation
- Reports for stakeholders
- README files
- Wiki pages

### Flags

| Flag | Effect |
|------|--------|
| `--format markdown` | Generate Markdown |
| `--format md` | Alias for markdown |

## SARIF

The SARIF (Static Analysis Results Interchange Format) format integrates with GitHub Code Scanning and other security tools.

### Features

- **Standard format**: OASIS SARIF 2.1.0
- **GitHub compatible**: Works with Code Scanning
- **Tool metadata**: Cancerbero version and info
- **Rule definitions**: Finding descriptions and help URLs

### Schema

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Cancerbero",
        "version": "0.1.0",
        "informationUri": "https://github.com/cancerbero-security/cancerbero",
        "rules": [...]
      }
    },
    "results": [...],
    "artifacts": [...],
    "invocations": [...]
  }]
}
```

### Result Levels

| Cancerbero Status | SARIF Level |
|-------------------|-------------|
| suspicious (critical/high) | error |
| suspicious (medium) | warning |
| suspicious (low/info) | note |
| error | error |
| unchecked | warning |
| clean/verified | none |

### When to Use

- GitHub Code Scanning
- GitLab SAST
- Security dashboards
- Compliance reporting
- Integration with security tools

### Flags

| Flag | Effect |
|------|--------|
| `--format sarif` | Generate SARIF |

## Choosing the Right Format

| Use Case | Recommended Format |
|----------|-------------------|
| Interactive review | Terminal |
| CI/CD pipeline | JSON |
| GitHub Code Scanning | SARIF |
| Documentation | Markdown |
| Audit trail | JSON |
| Quick check | Terminal + `--summary-only` |
| Integration with tools | JSON or SARIF |

## Format Comparison

| Feature | Terminal | JSON | Markdown | SARIF |
|---------|----------|------|----------|-------|
| Human readable | ✅ | ❌ | ✅ | ❌ |
| Machine readable | ❌ | ✅ | ❌ | ✅ |
| Deterministic | ❌ | ✅ | ❌ | ✅ |
| Colors/Icons | ✅ | ❌ | ❌ | ❌ |
| GitHub integration | ❌ | ❌ | ✅ | ✅ |
| CI/CD friendly | ❌ | ✅ | ❌ | ✅ |
| Shareable | ❌ | ❌ | ✅ | ❌ |
| Complete details | ✅ | ✅ | ✅ | ✅ |

## Examples

### Generate All Formats

```bash
# Terminal (default)
cancerbero check ./model.gguf

# JSON to file
cancerbero check ./model.gguf --json report.json

# JSON to stdout
cancerbero check ./model.gguf --json -

# Markdown to file
cancerbero check ./model.gguf --format markdown > report.md

# SARIF to file
cancerbero check ./model.gguf --format sarif > results.sarif
```

### Combine Formats

```bash
# Generate JSON and terminal simultaneously
cancerbero check ./model.gguf --json report.json

# Generate SARIF for GitHub and terminal for logs
cancerbero check ./model.gguf --format sarif > results.sarif
```

### Parse JSON Output

```python
import json
import subprocess

result = subprocess.run(
    ["cancerbero", "check", "./model.gguf", "--json", "-"],
    capture_output=True,
    text=True
)

report = json.loads(result.stdout)
print(f"Verdict: {report['verdict']}")
print(f"Findings: {len(report['findings'])}")
```
