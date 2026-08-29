# User Guides

Step-by-step guides for using Cancerbero effectively.

## Getting Started

- [Installation Guide](installation.md) — Get Cancerbero running in minutes
- [Quick Start](quickstart.md) — Your first model inspection
- [Configuration](configuration.md) — Customize Cancerbero for your workflow
- [Cancerbero for AI agents](agentic.md) — MCP server, JSON-schema tools, recipes
- [`AGENTS.md`](../../AGENTS.md) — The canonical agent contract

## Core Guides

- [How It Works](how-it-works.md) — Architecture and inspection pipeline
- [Understanding Reports](reports.md) — Interpreting findings and verdicts
- [Batch Processing](batch.md) — Checking multiple models efficiently

## Integration Guides

- [CI/CD Integration](cicd.md) — GitHub Actions, GitLab CI, Jenkins
- [Third-Party Delegates](delegates.md) — ModelAudit, PickleScan, Fickling, ModelScan
- [Custom Advisory Rules](custom-advisories.md) — Extending the knowledge bundle

## Reference

- [Hardening Recommendations](hardening.md) — Security best practices
- [Troubleshooting](troubleshooting.md) — Common issues and solutions
- [CLI Reference](../reference/cli.md) — Complete command-line documentation
- [Output Formats](../reference/output-formats.md) — Terminal, JSON, Markdown, SARIF
- [Finding Model](../reference/findings.md) — Status, severity, confidence explained
- [Exit Codes](../reference/exit-codes.md) — Exit code policy
- [Configuration File](../reference/config-file.md) — cancerbero.yaml reference
- [Agentic Tool Catalogue](../reference/agentic-tools.md) — MCP / JSON-schema reference

## Security Guides

- [Threat Model](../security/threat-model.md) — What Cancerbero protects against
- [Poisoned GGUF Templates](../security/poisoned-templates.md) — Inference-time backdoor detection
- [Rules File Backdoor](../security/rules-file-backdoor.md) — Companion file injection detection
- [Hugging Face UI Blindspot](../security/hf-ui-blindspot.md) — Multi-file template mismatch detection
- [Enhanced Template Security](../security/enhanced-template-security.md) — Dangerous functions, exfiltration, encoded instructions
- [Enhanced Companion Security](../security/enhanced-companion-security.md) — Hardcoded credentials, remote code execution, network exfiltration
- [Model Card Analysis](../security/model-card-analysis.md) — Credential harvesting, shortened URLs
- [Quantization Integrity](../security/quantization-integrity.md) — Tensor misalignment detection
- [Runtime Configuration Security](../security/runtime-config-security.md) — Network exposure, API key in args
- [Supply Chain Verification](../security/supply-chain-verification.md) — Impossible quantization, suspicious file types
- [Advisory Database](../security/advisories.md) — Known vulnerabilities and CVEs

## Examples

- [GitHub Actions](../examples/github-actions.yml) — Complete workflow example
- [GitLab CI](../examples/gitlab-ci.yml) — Complete CI configuration

## Quick Reference

### Common Commands

```bash
# Basic check (requires runtime for SUITABLE verdict)
cancerbero check ./model.gguf --runtime ./llama-cli --runtime-version b8146

# Directory scan
cancerbero check ./models/

# Hash verification
cancerbero check ./model.gguf --full --expected-sha256 abc123...

# JSON output
cancerbero check ./model.gguf --json report.json

# Markdown output
cancerbero check ./model.gguf --format markdown > report.md

# SARIF output
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

### Verdict Policy

Cancerbero uses a **severity × classification matrix** to determine verdicts:

| | Classification HIGH | Classification MEDIUM | Classification LOW |
|---|---|---|---|
| **Severity CRITICAL** | NOT SUITABLE | NOT SUITABLE | UNDETERMINED |
| **Severity HIGH** | NOT SUITABLE | UNDETERMINED | informational |
| **Severity MEDIUM/LOW** | UNDETERMINED | informational | informational |

### Core Checks

Cancerbero requires positive evidence from core checks for SUITABLE verdict:

1. **gguf_structure** — GGUF parsed successfully
2. **chat_template_static** — Template analyzed (present or absent)
3. **runtime_advisory_join** — Runtime version identified and checked

### Exit Codes

| Code | Verdict | Meaning | Action |
|---|---|---|---|
| `0` | `suitable` | Every core check (including the runtime advisory join) produced positive evidence | Continue |
| `0` | `clean` | No suspicious findings on the checks performed | Continue |
| `1` | `not_suitable` | A confirmed risk condition was found | Block |
| `2` | `undetermined` | A check could not complete or a non-runtime core check was missing | Review |
| `3` | (error) | Invalid input or operational failure | Fail |

### Output Formats

| Format | Use Case |
|--------|----------|
| Terminal | Interactive sessions |
| JSON | Automation, CI/CD |
| Markdown | Documentation, PRs |
| SARIF | GitHub Code Scanning |

## Learning Path

### Beginners

1. [Installation Guide](installation.md) — Install Cancerbero
2. [Quick Start](quickstart.md) — Run your first check
3. [Understanding Reports](reports.md) — Interpret results
4. [How It Works](how-it-works.md) — Understand the pipeline

### Intermediate Users

1. [Configuration](configuration.md) — Customize behavior
2. [Batch Processing](batch.md) — Check multiple models
3. [CI/CD Integration](cicd.md) — Automate checks
4. [Troubleshooting](troubleshooting.md) — Solve common issues

### Advanced Users

1. [Threat Model](../security/threat-model.md) — Understand threats
2. [Custom Advisory Rules](custom-advisories.md) — Extend advisories
3. [Output Formats](../reference/output-formats.md) — Integrate with tools
4. [Finding Model](../reference/findings.md) — Deep understanding

## Use Cases

### Individual Developer

```bash
# Check model before using (provide runtime for SUITABLE verdict)
cancerbero check ./my-model.gguf --runtime ./llama-cli --runtime-version b8146

# Verify integrity
cancerbero check ./my-model.gguf --full --expected-sha256 abc123...
```

### Team Lead

```bash
# Check all team models
cancerbero check ./team-models/ --json team-report.json

# Generate documentation
cancerbero check ./model.gguf --format markdown > model-report.md
```

### Security Engineer

```bash
# Security audit
cancerbero check ./models/ --verbose --json audit-report.json

# SARIF for GitHub
cancerbero check ./models/ --format sarif > results.sarif
```

### DevOps Engineer

```bash
# CI/CD integration
cancerbero check ./models/ --no-interactive --json report.json

# Gate deployment
cancerbero check ./model.gguf --no-interactive || exit 1
```

## Best Practices

### 1. Always Check Before Deployment

```bash
# Check model before loading (provide runtime for SUITABLE verdict)
cancerbero check ./model.gguf --runtime ./llama-cli --runtime-version b8146
```

### 2. Keep Cancerbero Updated

```bash
# Update for latest advisories
pip install --upgrade cancerbero
```

### 3. Provide Complete Information

```bash
# Provide runtime version for accurate checks
cancerbero check ./model.gguf --runtime ./llama-cli --runtime-version b8146
```

### 4. Use Configuration Files

```yaml
# cancerbero.yaml
runtime: /opt/llama.cpp/llama-cli
runtime_version: b8146
format: terminal
```

### 5. Generate Reports for Auditing

```bash
# Timestamped reports
cancerbero check ./model.gguf --json "reports/$(date +%Y%m%d)-model-check.json"
```

## Getting Help

### Documentation

- [README](../README.md) — Overview and quick start
- [Guides](index.md) — Step-by-step guides
- [Reference](../reference/index.md) — Technical reference
- [Security](../security/index.md) — Security documentation

### Community

- [GitHub Issues](https://github.com/noguerol/cancerbero/issues) — Bug reports
- [GitHub Discussions](https://github.com/noguerol/cancerbero/discussions) — Questions
- [Security Advisories](https://github.com/noguerol/cancerbero/security/advisories) — Vulnerabilities

### Support

- [Troubleshooting](troubleshooting.md) — Common issues
- [FAQ](troubleshooting.md#frequently-asked-questions) — Quick answers
- [Contact](mailto:support@cancerbero.dev) — Direct support
