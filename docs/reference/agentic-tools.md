# Reference — agentic tool catalogue

This document is the machine-readable contract for every agent
surface of Cancerbero. It is generated from
`src/cancerbero/agentic/schemas.py`; if it disagrees with the
source, the source wins.

Run `cancerbero agentic-manifest` to print the same catalogue
in Anthropic's `tools` format.

## `cancerbero_inspect`

Run the full Cancerbero check on one or more targets. Returns the
verdict, the list of findings, optional SHA-256 digests, and the
per-artifact / per-runtime facts.

This is the default tool to call when an agent needs to decide
whether a GGUF artifact and an optional llama.cpp runtime are
safe to load.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `targets` | array of string | yes | One or more paths. A path may be a single `.gguf` file, a directory of GGUFs, or a llama.cpp binary. Directory targets are expanded to all GGUF files inside. |
| `runtime` | string | no | Path to a llama.cpp runtime binary. When set, Cancerbero joins the advisory bundle against the detected runtime build. |
| `runtime_version` | string | no | Override the runtime version, e.g. `b8146` or `0.2.72`. |
| `full_hash` | boolean | no (default `false`) | Stream each artifact to compute a complete SHA-256. Slower but enables provenance checks. |
| `expected_sha256` | string | no | Expected digest of the FIRST target (64 hex chars). Forces `full_hash` and surfaces a SUSPICIOUS finding on mismatch. |

**Output shape:**

```json
{
  "verdict": "suitable" | "not_suitable" | "undetermined" | "clean",
  "exit_code": 0 | 1 | 2,
  "summary": "...",
  "artifacts": [
    {
      "path": "...",
      "name": "...",
      "architecture": "...",
      "gguf_version": 2 | 3,
      "tensor_count": 0,
      "metadata_count": 0,
      "file_size": 0,
      "has_chat_template": true,
      "sha256": "..." | null,
      "omitted_metadata_keys": []
    }
  ],
  "runtimes": [
    {
      "path": "...",
      "component": "llama.cpp" | "llama-cpp-python" | "sglang" | "ollama",
      "version": "...",
      "build": 0 | null,
      "commit": "..." | null,
      "confidence": "high" | "medium" | "low"
    }
  ],
  "findings": [],
  "bundle": { "version": "..." }
}
```

## `cancerbero_artifact_facts`

Read the GGUF metadata and tensor descriptors of a single artifact
WITHOUT running template or companion analysis. Useful as a fast
first step before deciding whether the full check is warranted.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `path` | string | yes | Path to a single `.gguf` file. |

**Output shape:**

```json
{
  "path": "...",
  "name": "...",
  "architecture": "...",
  "gguf_version": 2 | 3,
  "tensor_count": 0,
  "metadata_count": 0,
  "file_size": 0,
  "alignment": 32,
  "has_chat_template": true,
  "sha256": "..." | null,
  "omitted_metadata_keys": [],
  "tensors": [{"name": "...", "dimensions": [], "ggml_type": 0, "byte_size": 0}],
  "metadata": {"key": "value"},
  "structural_findings": []
}
```

## `cancerbero_check_template`

Run the chat-template analysis on a single template string
WITHOUT needing a GGUF file. Reports AST findings, SSTI gadgets,
exfiltration URLs, and prompt-injection patterns.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `template` | string | yes | Raw Jinja2 template text to inspect. |

**Output shape:**

```json
{
  "verdict": "...",
  "summary": "...",
  "findings": [
    {
      "id": "cbr.template.security.dangerous_function.0",
      "head": "loading",
      "check": "template_enhanced_security",
      "status": "suspicious",
      "severity": "high",
      "confidence": "high",
      "classification": "high",
      "summary": "...",
      "action": "...",
      "evidence": {"line": 1, "pattern": "..."},
      "references": [],
      "mandatory": true
    }
  ]
}
```

## `cancerbero_companion_scan`

Run the companion-file security scan on a directory without
inspecting a GGUF file. Detects hardcoded credentials, Modelfile
FROM URLs, Rules File Backdoor patterns, and metadata mismatches.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `directory` | string | yes | Path to a directory of companion files. |

**Output shape:**

```json
{
  "summary": "...",
  "files_inspected": ["config.json", "Modelfile"],
  "findings": [],
  "errors": [],
  "limit_reached": false,
  "bytes_read": 0
}
```

## `cancerbero_list_advisories`

Return the list of advisories bundled with this Cancerbero
installation. Each entry includes the affected component, build /
version range, severity, and source URL.

**Parameters:** none.

**Output shape:**

```json
{
  "bundle_version": "2026.08.28.3",
  "advisory_count": 9,
  "advisories": [
    {
      "id": "CVE-2024-32878",
      "title": "...",
      "source": "https://...",
      "component": "llama.cpp",
      "version_scheme": "llama_cpp_build",
      "affected": {"lte": 2715},
      "fixed": {"gte": 2740},
      "artifact_predicates": [...],
      "severity": "high",
      "confidence": "high",
      "explanation": "...",
      "action": "...",
      "published": "2024-04-26",
      "reviewed": "2026-08-28"
    }
  ]
}
```

## `cancerbero_hash`

Compute the SHA-256 of a file and optionally compare it against an
expected digest. Fast (no template or companion analysis).

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `path` | string | yes | Path to a file. |
| `expected` | string | no | 64-character hex SHA-256 to compare against. |

**Output shape:**

```json
{
  "path": "...",
  "size_bytes": 0,
  "sha256": "...",
  "expected": "..." | null,
  "match": true | false | null,
  "throughput_bytes_per_second": 0,
  "elapsed_seconds": 0
}
```

`match` is `null` when no expected digest was supplied.

## `cancerbero_self_test`

Run a self-test against a list of known-safe and known-bad fixtures
bundled with Cancerbero. Returns the count of true positives, true
negatives, false positives, and false negatives.

**Parameters:** none.

**Output shape:**

```json
{
  "true_positives": 0,
  "true_negatives": 0,
  "false_positives": 0,
  "false_negatives": 0
}
```

A non-zero `false_positives` or `false_negatives` count indicates
the installation is broken or has been monkey-patched; do not
trust its verdicts until you understand why.

## Stable finding identifiers

Every finding carries an `id` of the form `cbr.<head>.<check>.<kind>[.<index>]`.
These identifiers are stable across releases (within a major
version) and may be used in agent rules, monitoring alerts, and
test assertions. Common prefixes:

- `cbr.gguf.*` — GGUF parser, metadata, tensor descriptors
- `cbr.template.*` — chat-template analysis (parsed, constructs,
  security, poison)
- `cbr.config.*` — companion-file analysis
- `cbr.config.companion_security_*` — high-signal companion patterns
- `cbr.config.rules_backdoor_*` — Rules File Backdoor patterns
- `cbr.identity.*` — SHA-256 and provenance findings
- `cbr.join.*` — runtime advisory join findings
- `cbr.runtime.*` — runtime identification / flags
- `cbr.supply_chain.*` — supply chain verification
- `cbr.quantization_integrity.*` — parser-rejected tensor invariants
