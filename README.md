<p align="center">
  <img src="docs/assets/cancerbero-banner.png" alt="Cancerbero" width="900">
</p>

# Cancerbero

Cancerbero is a local, offline-first command-line tool that inspects GGUF artifacts **before** they are handed to a llama.cpp runtime. It answers bounded questions about artifact structure, declared identity, chat-template risk, companion configuration, and the applicability of known runtime advisories.

Cancerbero does **not** claim that a model is safe, prove the absence of backdoors, execute the model, or inspect tensor contents. Its output separates observed facts, suspicious findings, missing coverage, and check errors.

> **Status:** `0.1.0` alpha. Supports GGUF and llama.cpp only.

## For AI agents

Cancerbero ships with a first-class **agentic surface**: a
[Model Context Protocol](https://modelcontextprotocol.io) server, a
JSON-schema tool catalogue, and a comprehensive
[`AGENTS.md`](./AGENTS.md) guide. Claude Code, OpenAI Codex CLI,
Cursor, and any MCP-aware client can drive Cancerbero as native
tool calls; the catalogue is the single source of truth shared with
non-MCP clients.

```json
{
  "mcpServers": {
    "cancerbero": {
      "command": "cancerbero",
      "args": ["mcp"]
    }
  }
}
```

The agent then has access to seven tools — `cancerbero_inspect`,
`cancerbero_artifact_facts`, `cancerbero_check_template`,
`cancerbero_companion_scan`, `cancerbero_list_advisories`,
`cancerbero_hash`, `cancerbero_self_test` — each with stable
parameters and machine-readable JSON output. See
[`AGENTS.md`](./AGENTS.md) and [`docs/guides/agentic.md`](./docs/guides/agentic.md)
for the full contract.

## Why Cancerbero?

## Why Cancerbero?

A model file and its runtime form one attack surface. A structurally valid artifact can still expose a vulnerable parser or template path in a particular runtime build. Cancerbero's core operation is a local join:

```text
artifact properties × runtime identity/build × versioned advisory knowledge
```

The result is `SUITABLE`, `NOT SUITABLE`, or `UNDETERMINED` **for the checks performed**—never a generic security seal or numeric score.

### Verdict Policy

Cancerbero uses a **severity × classification matrix** to determine verdicts:

| | Classification HIGH | Classification MEDIUM | Classification LOW |
|---|---|---|---|
| **Severity CRITICAL** | NOT SUITABLE | NOT SUITABLE | UNDETERMINED |
| **Severity HIGH** | NOT SUITABLE | UNDETERMINED | informational |
| **Severity MEDIUM/LOW** | UNDETERMINED | informational | informational |

Cancerbero requires **positive evidence from core checks** before producing a `SUITABLE` verdict:

1. **gguf_structure** — GGUF parsed successfully
2. **chat_template_static** — Template analyzed (present or absent)
3. **runtime_advisory_join** — Runtime version identified and checked

If any core check is missing (unchecked/error), the verdict is `UNDETERMINED`.

## Installation

Requires Python 3.10+.

```bash
# Install from source
python -m pip install .

# Development installation
python -m pip install -e ".[dev]"
```

One small runtime dependency (Jinja2 for template AST analysis). No PyTorch, Transformers, TensorFlow, or JAX.

## Quick start

```bash
# Inspect a GGUF file (requires runtime for SUITABLE verdict)
cancerbero check ./model.gguf --runtime ./llama-cli --runtime-version b8146

# Inspect a directory of models
cancerbero check ./models/

# Verify SHA-256 digest
cancerbero check ./model.gguf --full --expected-sha256 <64-hex>

# Generate JSON report
cancerbero check ./model.gguf --json report.json

# Generate Markdown report (for PRs and documentation)
cancerbero check ./model.gguf --format markdown > report.md

# Generate SARIF report (for GitHub Code Scanning)
cancerbero check ./model.gguf --format sarif > results.sarif

# Verbose mode (shows template analysis and notes)
cancerbero check ./model.gguf --verbose

# Explain a specific finding
cancerbero check ./model.gguf --explain cbr.gguf.inspection_error

# Quick summary (just the verdict)
cancerbero check ./model.gguf --summary-only
```

## What it checks

### Structure
GGUF v2/v3 header, metadata types, tensor descriptors, alignment, offsets, overlap validation. Supports standard types plus ROCmFP4/ROCmFPX experimental types (100–108).

### Template Security
Static Jinja AST analysis with enhanced security patterns:

- **Poisoned GGUF Templates** (Pillar Security) — Conditional triggers, hidden instructions, exfiltration URLs
- **Dangerous functions** — os.system, subprocess, eval, exec in templates
- **Encoded payloads** — Base64, Unicode tag smuggling, zero-width characters
- **Data exfiltration** — URLs with data parameters, Markdown image exfiltration

### Companion File Security
Inspects `config.json`, `tokenizer_config.json`, `Modelfile`, manifests, adapters, and `.py` files:

- **Hardcoded credentials** — API keys, AWS credentials, private keys, passwords
- **Remote code execution** — trust_remote_code, auto_map, remote URLs
- **Network exfiltration** — Discord/Slack webhooks, URLs with data parameters

### Model Card Analysis
Inspects README.md, model cards, and dataset cards:

- **Credential harvesting** — Instructions to exfiltrate credentials
- **Shortened URLs** — URLs that can hide malicious destinations

### Quantization Integrity
Analyzes GGUF tensor quantization for potential security issues:

- **Tensor misalignment** — Tensors with offset not aligned to alignment

### Runtime Configuration Security
Analyzes llama.cpp runtime configuration for security issues:

- **Network exposure** — --host 0.0.0.0 (bind to all interfaces)
- **Credential exposure** --api-key in command line arguments

### Supply Chain Verification
Detects supply chain risks in model artifacts:

- **Impossible quantization** — Quantization types that don't exist
- **Suspicious file types** — Executable extensions

### Advisory Join
Crosses artifact properties with runtime build against versioned CVE knowledge. Seven advisories included:

| Advisory | Component | Severity | Source |
|----------|-----------|----------|--------|
| CVE-2024-32878 | llama.cpp | HIGH | GHSA-p5mv-gjc5-mwqv |
| CVE-2024-34359 | llama-cpp-python | CRITICAL | GHSA-56xg-wfcc-g829 |
| CVE-2026-27940 | llama.cpp | HIGH | GHSA-3p4r-fq3f-q74v |
| CVE-2026-33298 | llama.cpp | HIGH | GHSA-96jg-mvhq-q7q7 |
| CVE-2026-5760 | SGLang | HIGH | CVE-2026-5760 |
| CVE-2026-7482 | Ollama | CRITICAL | GHSA-x8qc-fggm-mpqg |
| GGUF-2026-05-001 | llama.cpp | HIGH | oss-security 2026-05-15 |

### Hash
Optional streaming SHA-256 with constant-time digest comparison.

### Third-Party Tool Delegates
Optional integrations with specialized security tools:

- **ModelAudit** — 42+ format scanning (`--modelaudit`)
- **PickleScan** — Pickle bytecode analysis (`--picklescan`)
- **Fickling** — Allowlist-based pickle scanning (`--fickling`)
- **ModelScan** — Multi-framework model scanning (`--modelscan`)
- **All delegates** — Run all available tools (`--all-delegates`)

### Configuration Hardening Recommendations
Generates actionable security recommendations:

- **Runtime** — Update llama.cpp, provide runtime version
- **Network** — Restrict access, use environment variables
- **Template** — Don't load suspicious templates
- **Companion** — Remove credentials, trust_remote_code
- **Supply chain** — Verify model source
- **General** — Prefer safetensors, always check first

## Output formats

### Terminal (default)
Human-readable output with clear sections for findings, errors, and coverage.

### JSON
Deterministic, machine-readable output for automation and CI/CD integration.

### Markdown
Shareable reports suitable for PRs, issues, and documentation. Includes tables, badges, and structured sections.

### SARIF
Compatible with GitHub Code Scanning and other static analysis tools. Maps findings to standard SARIF result levels.

## Exit codes

| Code | Verdict | Meaning |
|---:|---|---|
| `0` | `suitable` | Every core check (including the runtime advisory join) produced positive evidence |
| `0` | `clean` | No suspicious findings on the checks performed (typically: no `--runtime` supplied) |
| `1` | `not_suitable` | A confirmed risk condition was found |
| `2` | `undetermined` | A check could not complete or a non-runtime core check was missing |
| `3` | (error) | Invalid input or operational failure |

## Options

```
cancerbero check TARGET [TARGET ...]
  --runtime PATH              Explicit llama.cpp executable
  --runtime-version VALUE     Trusted build/version override (e.g. b8146)
  --full                      Calculate SHA-256 (reads entire file)
  --expected-sha256 HEX       Expected digest (implies --full)
  --allow-runtime-exec        Opt-in: run runtime with --version
  --format FORMAT             Output format: terminal, json, markdown, md, sarif
  --json PATH|-               Write canonical JSON (implies --format json)
  --include-observations      Include timings in JSON
  --verbose                   Show technical evidence and notes
  --explain FINDING_ID        Show detailed explanation for a finding
  --summary-only              Show only the verdict line
  --no-color                  Disable terminal color
  --no-banner                 Skip ASCII art banner
  --no-interactive            Disable interactive prompts (for CI/CD)
  --config PATH               Path to configuration file
  --modelaudit                Run ModelAudit for broad format scanning
  
  --picklescan                Run PickleScan for pickle bytecode analysis
  --fickling                  Run Fickling for allowlist-based pickle scanning
  --modelscan                 Run ModelScan for multi-framework model scanning
  --all-delegates             Run all available delegates
```

## Configuration file

Create `cancerbero.yaml` in your project root or `~/.cancerbero/config.yaml`:

```yaml
runtime: /path/to/llama-cli
runtime_version: b8146
format: terminal
verbose: false
```

Environment variable `CANCERBERO_CONFIG` can specify a custom config path.

## Security boundaries

Cancerbero **does not**:
- Certify an artifact as "safe" or free of backdoors
- Load models or render templates in the default path
- Execute discovered runtimes automatically
- Access the network or send telemetry
- Inspect tensor data or weight contents
- Patch or modify suspicious artifacts

If a risk is found, prefer: updating the runtime, isolating the artifact, obtaining a trusted pinned copy, or replacing it.

## Documentation

- [User Guides](docs/guides/) — Installation, quickstart, configuration, CI/CD
- [Security](docs/security/) — Threat model, attack vectors, detection capabilities
- [Reference](docs/reference/) — CLI, output formats, findings, exit codes
- [Examples](docs/examples/) — GitHub Actions, GitLab CI

## Development

```bash
pytest                          # Run all tests (287 tests)
ruff check src tests            # Lint
python -m build                 # Build wheel
python fuzz/fuzz_gguf.py tests/corpus/gguf  # Fuzz parser
```

CI tests Python 3.10/3.13 on Linux, macOS, and Windows.

## License

Apache License 2.0. See [LICENSE](LICENSE).
