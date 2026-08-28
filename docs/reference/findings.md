# Finding Model

Cancerbero's finding model provides a structured, multi-dimensional approach to reporting security observations. Unlike binary pass/fail systems, Cancerbero separates findings into distinct dimensions that provide actionable intelligence.

## Finding Dimensions

### Status

The status indicates the outcome of a specific check:

| Status | Icon | Meaning | Blocks SUITABLE? |
|--------|------|---------|------------------|
| `verified` | ✅ | Check passed with positive confirmation | No |
| `clean` | ✅ | Check passed without suspicious findings | No |
| `suspicious` | ⚠️ | Check found a confirmed risk condition | **Yes** |
| `unchecked` | ❓ | Check could not be completed | If mandatory |
| `not_applicable` | ➖ | Check does not apply to this artifact/runtime | No |
| `error` | ❌ | Check failed due to operational error | If mandatory |

### Severity

Severity indicates the potential impact of a finding (only for `suspicious` status):

| Severity | Description | Example |
|----------|-------------|---------|
| `info` | Informational observation | Template has no risky constructs |
| `low` | Minor risk, unlikely to cause harm | Companion file has remote reference |
| `medium` | Moderate risk, may cause issues | Runtime binary writable by others |
| `high` | Significant risk, likely to cause harm | Known CVE affects runtime |
| `critical` | Severe risk, immediate action required | Template injection vulnerability |

### Confidence

Confidence indicates how certain Cancerbero is about a finding:

| Confidence | Description | Example |
|------------|-------------|---------|
| `low` | Limited evidence, may be false positive | Static binary string detection |
| `medium` | Moderate evidence, likely accurate | Git metadata detection |
| `high` | Strong evidence, very likely accurate | Explicit build file, hash match |

## Finding Structure

Each finding contains:

```json
{
  "id": "cbr.template.poison.conditional_trigger",
  "head": "loading",
  "check": "template_poison_detection",
  "status": "suspicious",
  "severity": "high",
  "confidence": "medium",
  "summary": "Template contains conditional logic that activates on sensitive keywords.",
  "evidence": {
    "pattern": "conditional_trigger",
    "line": 5,
    "kind": "poison_conditional_trigger"
  },
  "action": "Do not load this model...",
  "references": [
    "https://www.pillar.security/blog/..."
  ],
  "mandatory": true
}
```

### Fields Explained

| Field | Description |
|-------|-------------|
| `id` | Unique identifier for the finding type |
| `head` | Which "head" of Cancerbero produced it (provenance, loading, behavior) |
| `check` | Specific check that generated the finding |
| `status` | Outcome of the check |
| `severity` | Potential impact (only for suspicious) |
| `confidence` | Certainty level |
| `summary` | Human-readable description |
| `evidence` | Technical details supporting the finding |
| `action` | Recommended remediation steps |
| `references` | URLs to relevant documentation |
| `mandatory` | Whether this finding affects the verdict |

## Finding Categories

### Provenance Findings

Findings related to artifact identity and integrity:

| ID | Description | Status |
|----|-------------|--------|
| `cbr.identity.digest_match` | SHA-256 matches expected digest | verified |
| `cbr.identity.digest_mismatch` | SHA-256 does not match expected digest | suspicious |
| `cbr.identity.digest_absent` | No expected digest provided | unchecked |

### Loading Findings

Findings related to artifact structure and runtime compatibility:

| ID | Description | Status |
|----|-------------|--------|
| `cbr.gguf.inspection_error` | GGUF parsing failed | error |
| `cbr.gguf.metadata_pattern` | Suspicious metadata pattern detected | unchecked |
| `cbr.gguf.zero_dimension` | Tensor has zero-sized dimension | suspicious |
| `cbr.runtime.unknown_build` | Runtime build could not be identified | unchecked |
| `cbr.runtime.writable_by_others` | Runtime binary writable by others | suspicious |
| `cbr.join.known_advisory` | Known advisory applies to runtime | suspicious/verified |

### Template Findings

Findings related to chat template analysis:

| ID | Description | Status |
|----|-------------|--------|
| `cbr.template.absent` | No chat template found | not_applicable |
| `cbr.template.static_clean` | Template parsed without risky constructs | clean |
| `cbr.template.syntax` | Template has syntax errors | error |
| `cbr.template.constructs` | Template has risky constructs | unchecked |
| `cbr.template.poison.*` | Poisoned template pattern detected | suspicious/unchecked |

### Configuration Findings

Findings related to companion files:

| ID | Description | Status |
|----|-------------|--------|
| `cbr.config.auto_map` | auto_map detected in config | unchecked |
| `cbr.config.trust_remote_code` | trust_remote_code enabled | unchecked |
| `cbr.config.remote_reference_*` | Remote reference detected | unchecked |
| `cbr.config.rules_backdoor_*` | Rules File Backdoor pattern detected | suspicious/unchecked |
| `cbr.config.template_mismatch` | Templates differ across GGUF files | suspicious |

## Verdict Logic

The verdict is determined by the findings:

```
IF any finding is SUSPICIOUS
  THEN verdict = NOT SUITABLE (exit 1)

ELSE IF any mandatory finding is UNCHECKED or ERROR
  THEN verdict = UNDETERMINED (exit 2)

ELSE
  THEN verdict = SUITABLE (exit 0)
```

### Important Rules

1. **Only `suspicious` findings block SUITABLE** — unchecked and error findings produce UNDETERMINED
2. **Non-mandatory findings don't affect verdict** — informational findings are advisory only
3. **No global score** — each finding is evaluated independently
4. **Coverage is always reported** — users see what was and wasn't checked

## Example Findings

### Example 1: Vulnerable Runtime

```json
{
  "id": "cbr.join.CVE-2026-27940",
  "head": "loading",
  "check": "runtime_advisory_join",
  "status": "suspicious",
  "severity": "high",
  "confidence": "high",
  "summary": "GHSA-3p4r-fq3f-q74v: heap buffer overflow in GGUF mem_size calculation",
  "evidence": {
    "advisory": "CVE-2026-27940",
    "runtime_build": 5000,
    "applicability": "affected"
  },
  "action": "Do not load the artifact with this runtime; update llama.cpp to build b8146 or later.",
  "references": ["https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-3p4r-fq3f-q74v"],
  "mandatory": true
}
```

### Example 2: Poisoned Template

```json
{
  "id": "cbr.template.poison.conditional_trigger",
  "head": "loading",
  "check": "template_poison_detection",
  "status": "suspicious",
  "severity": "high",
  "confidence": "medium",
  "summary": "Template contains conditional logic that activates on sensitive keywords.",
  "evidence": {
    "pattern": "conditional_trigger",
    "line": 5,
    "kind": "poison_conditional_trigger"
  },
  "action": "Do not load this model. The template contains patterns consistent with a Poisoned GGUF Template attack.",
  "references": ["https://www.pillar.security/blog/..."],
  "mandatory": true
}
```

### Example 3: Informational Finding

```json
{
  "id": "cbr.template.constructs",
  "head": "loading",
  "check": "chat_template_static",
  "status": "unchecked",
  "severity": "low",
  "confidence": "high",
  "summary": "Template contains 80 static construct(s): attribute_access×56, call×20, macro.",
  "evidence": {
    "construct_count": 80,
    "kinds": {"attribute_access": 56, "call": 20, "macro": 1}
  },
  "mandatory": false
}
```

## Best Practices

### For Users

1. **Always check the full report**, not just the verdict
2. **Investigate all suspicious findings** before deploying
3. **Understand the context** — some findings may be acceptable for your use case
4. **Keep Cancerbero updated** for latest advisory database

### For Automation

1. **Use exit codes** for CI/CD gating
2. **Parse JSON output** for detailed analysis
3. **Set `--no-interactive`** for non-interactive environments
4. **Configure `--format`** for integration with other tools
