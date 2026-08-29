# Reference Documentation

Technical reference documentation for Cancerbero.

## CLI Reference

- [CLI Reference](cli.md) — Complete command-line documentation
- [Global Options](cli.md#global-options) — Options that apply to all commands
- [Check Command](cli.md#check) — The main inspection command
- [Output Formats](cli.md#output-formats) — Terminal, JSON, Markdown, SARIF

## Output Formats

- [Output Formats](output-formats.md) — Detailed format documentation
- [Terminal Format](output-formats.md#terminal-default) — Human-readable output
- [JSON Format](output-formats.md#json) — Machine-readable output
- [Markdown Format](output-formats.md#markdown) — Documentation-ready output
- [SARIF Format](output-formats.md#sarif) — GitHub Code Scanning integration

## Finding Model

- [Finding Model](findings.md) — How findings work
- [Finding Dimensions](findings.md#finding-dimensions) — Status, severity, confidence, classification
- [Finding Categories](findings.md#finding-categories) — Provenance, loading, template, configuration
- [Verdict Logic](findings.md#verdict-logic) — How verdicts are determined

## Exit Codes

- [Exit Codes](exit-codes.md) — Exit code documentation
- [Exit Code Summary](exit-codes.md#exit-code-summary) — Quick reference
- [Using Exit Codes](exit-codes.md#using-exit-codes-in-scripts) — Scripting examples

## Configuration

- [Configuration File](config-file.md) — Configuration file reference
- [Configuration Options](config-file.md#configuration-options) — All available options
- [Environment Variables](config-file.md#environment-variables) — Environment variable reference
- [Precedence](config-file.md#precedence) — How configuration is applied

## Verdict Policy

Cancerbero uses a **severity × classification matrix** to determine verdicts:

| | Classification HIGH | Classification MEDIUM | Classification LOW |
|---|---|---|---|
| **Severity CRITICAL** | NOT SUITABLE | NOT SUITABLE | UNDETERMINED |
| **Severity HIGH** | NOT SUITABLE | UNDETERMINED | informational |
| **Severity MEDIUM/LOW** | UNDETERMINED | informational | informational |

### Core Checks

| Check | Description |
|-------|-------------|
| `gguf_structure` | GGUF parsed successfully |
| `chat_template_static` | Template analyzed (present or absent) |
| `runtime_advisory_join` | Runtime version identified and checked |

### Verdict Logic

| Scenario | Verdict | Exit Code |
|----------|---------|-----------|
| All core checks pass, no blocking findings | SUITABLE | 0 |
| High-confidence suspicious finding | NOT SUITABLE | 1 |
| Medium-confidence suspicious finding | UNDETERMINED | 2 |
| Missing core check | UNDETERMINED | 2 |
| Error condition | UNDETERMINED | 2 |

## Advisory Bundle

The advisory bundle contains 9 advisories:

| Advisory | Component | Severity | Source |
|----------|-----------|----------|--------|
| CVE-2024-32878 | llama.cpp | HIGH | GHSA-p5mv-gjc5-mwqv |
| CVE-2024-34359 | llama-cpp-python | CRITICAL | GHSA-56xg-wfcc-g829 |
| CVE-2026-27940 | llama.cpp | HIGH | GHSA-3p4r-fq3f-q74v |
| CVE-2026-33298 | llama.cpp | HIGH | GHSA-96jg-mvhq-q7q7 |
| CVE-2026-5760 | SGLang | HIGH | CVE-2026-5760 |
| CVE-2026-7482 | Ollama | CRITICAL | GHSA-x8qc-fggm-mpqg |
| GGUF-2026-05-001 | llama.cpp | HIGH | oss-security 2026-05-15 |
| GHSA-6hc7-9rph-cm99 | llama.cpp | CRITICAL | CVE-2026-43631 (RCE in llama-server --sleep-idle-seconds) |
| GHSA-vgg9-87g3-85w8 | llama.cpp | HIGH | CVE-2025-53630 (GGUF parser integer overflow) |

Each advisory includes:
- `verified_by` — Source verification
- `fixed_inferred` — Whether the fix build was inferred (default: false)

## Data Formats

### GGUF Format

Cancerbero parses GGUF v2 and v3 files:

- **Header**: Magic bytes, version, tensor count, metadata count
- **Metadata**: Key-value pairs with typed values
- **Tensor Descriptors**: Names, dimensions, types, offsets
- **Alignment**: Data block alignment

### Advisory Bundle

The knowledge bundle contains:

- **Schema version**: Bundle format version
- **Bundle version**: Release version
- **Advisories**: Array of advisory rules
- **Integrity**: SHA-256 digest

### Finding Schema

```json
{
  "id": "cbr.gguf.parsed",
  "head": "loading",
  "check": "gguf_structure",
  "status": "clean",
  "severity": "info",
  "confidence": "high",
  "classification": "high",
  "summary": "GGUF file parsed successfully.",
  "evidence": {...},
  "action": null,
  "references": [],
  "mandatory": false
}
```

### Report Schema

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

## Version Information

| Property | Value |
|----------|-------|
| Current Version | 0.1.0 |
| Python Required | 3.10+ |
| Supported Formats | GGUF v2, GGUF v3 |
| Supported Runtimes | llama.cpp |
| Dependencies | Jinja2 |
| License | Apache 2.0 |

## API Reference

### Agentic tool catalogue

Cancerbero exposes seven stable tool calls for AI agents via the
Model Context Protocol and as JSON-schema definitions. See
[`agentic-tools.md`](agentic-tools.md) for the full reference
(per-tool parameters, output shapes, finding ID prefixes). The
canonical agent contract lives in [`AGENTS.md`](../../AGENTS.md).

### Python API

Cancerbero can be used as a Python library:

```python
from cancerbero.audit import CheckOptions, run_check
from cancerbero.agentic.dispatch import safe_invoke_tool
from cancerbero.report import render_terminal, canonical_json

# Option 1: programmatic check
options = CheckOptions(
    targets=(Path("./model.gguf"),),
    runtime=Path("./llama-cli"),
    runtime_version="b8146",
)
report = run_check(options, command=["cancerbero", "check", "./model.gguf"])
terminal = render_terminal(report)
json_output = canonical_json(report)

# Option 2: agentic tool (the same code path as the MCP server)
result = safe_invoke_tool(
    "cancerbero_inspect",
    {
        "targets": ["./model.gguf"],
        "runtime": "./llama-cli",
        "runtime_version": "b8146",
    },
)
if result["verdict"] == "not_suitable":
    for f in result["findings"]:
        if f["status"] == "suspicious":
            print(f["id"], f["summary"])
```

### Key Classes

| Class | Module | Description |
|-------|--------|-------------|
| `CheckOptions` | `cancerbero.audit` | Check configuration |
| `AuditReport` | `cancerbero.domain` | Complete report |
| `Finding` | `cancerbero.domain` | Individual finding |
| `ArtifactFacts` | `cancerbero.domain` | Artifact properties |
| `RuntimeFacts` | `cancerbero.domain` | Runtime properties |
| `ToolDefinition` | `cancerbero.agentic.schemas` | One agent-callable tool |
| `KnowledgeBundle` | `cancerbero.knowledge.schema` | Validated advisory bundle |

### Key Functions

| Function | Module | Description |
|----------|--------|-------------|
| `run_check()` | `cancerbero.audit` | Run inspection |
| `render_terminal()` | `cancerbero.report` | Render terminal output |
| `canonical_json()` | `cancerbero.report` | Generate JSON |
| `render_markdown()` | `cancerbero.report` | Generate Markdown |
| `render_sarif()` | `cancerbero.report` | Generate SARIF |
| `inspect_gguf()` | `cancerbero.gguf.inspector` | Inspect GGUF file |
| `inspect_runtime()` | `cancerbero.runtime.inspector` | Inspect runtime |
| `safe_invoke_tool()` | `cancerbero.agentic.dispatch` | Dispatch an agent tool call |
| `tool_definitions_as_anthropic_tools()` | `cancerbero.agentic.schemas` | Render Anthropic tool catalogue |
| `tool_definitions_as_openai_tools()` | `cancerbero.agentic.schemas` | Render OpenAI tool catalogue |

## Error Reference

### Error Types

| Error | Module | Description |
|-------|--------|-------------|
| `GgufError` | `cancerbero.gguf.reader` | Base GGUF error |
| `GgufMagicError` | `cancerbero.gguf.reader` | Invalid magic bytes |
| `GgufVersionError` | `cancerbero.gguf.reader` | Unsupported version |
| `GgufTruncatedError` | `cancerbero.gguf.reader` | File truncated |
| `GgufLimitError` | `cancerbero.gguf.reader` | Limit exceeded |
| `GgufTypeError` | `cancerbero.gguf.reader` | Invalid type |
| `GgufDuplicateError` | `cancerbero.gguf.reader` | Duplicate key |
| `GgufValidationError` | `cancerbero.gguf.reader` | Validation failed |
| `GgufRangeError` | `cancerbero.gguf.reader` | Range invalid |
| `RuntimeInspectionError` | `cancerbero.runtime.inspector` | Runtime error |
| `BundleError` | `cancerbero.knowledge.schema` | Bundle error |
| `BundleSchemaError` | `cancerbero.knowledge.schema` | Schema error |
| `BundleIntegrityError` | `cancerbero.knowledge.loader` | Integrity error |
| `BundleIOError` | `cancerbero.knowledge.loader` | I/O error |

## Performance Reference

### Metadata-Only Inspection

| File Size | Time | Bytes Read | Percentage |
|-----------|------|------------|------------|
| 1 GB | < 1s | ~10 MB | ~1% |
| 10 GB | < 2s | ~15 MB | ~0.15% |
| 50 GB | < 5s | ~20 MB | ~0.04% |

### Hash Calculation

| File Size | Time | Throughput |
|-----------|------|------------|
| 1 GB | ~2s | ~500 MB/s |
| 10 GB | ~20s | ~500 MB/s |
| 50 GB | ~100s | ~500 MB/s |

### Memory Usage

| Operation | Peak Memory |
|-----------|-------------|
| Metadata inspection | < 100 MB |
| Hash calculation | < 50 MB |
| Template analysis | < 50 MB |
| Full check | < 200 MB |

## Limitations Reference

### What Cancerbero Can Detect

- Known runtime vulnerabilities (via advisory join)
- Suspicious template patterns (via static analysis)
- Malicious companion files (via pattern matching)
- Template mismatches across files
- Structural GGUF issues
- Hardcoded credentials
- Remote code execution configurations
- Network exfiltration patterns
- Tensor misalignment
- Network exposure

### What Cancerbero Cannot Detect

- Backdoors in model weights
- Novel, unknown vulnerabilities
- Behavior that only manifests during execution
- Sophisticated obfuscation that evades pattern matching
- Zero-day exploits

## Changelog

See [CHANGELOG.md](../../CHANGELOG.md) for version history.

## License

Cancerbero is licensed under the Apache License 2.0. See [LICENSE](../../LICENSE) for details.
