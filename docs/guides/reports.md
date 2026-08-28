# Understanding Reports

This guide explains how to interpret Cancerbero's reports and findings.

## Report Structure

### Terminal Report

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

⚠  FINDINGS
  [HIGH] Template contains dangerous function calls
         → Do not load this model...
         Check: template_poison_detection (suspicious)

ℹ  NOTES
  - Metadata key 'general.repo_url' contains url in metadata

COVERAGE
  3 clean · 4 unchecked

  This is a suitability assessment, not a safety certification.
  Absence of findings does not prove the artifact is safe.
```

### JSON Report

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

## Verdict Policy

Cancerbero requires **positive evidence from core checks** before producing a `SUITABLE` verdict. This prevents the "SUITABLE on no evidence" problem.

### Core Checks

| Check | Description |
|-------|-------------|
| `gguf_structure` | GGUF parsed successfully |
| `chat_template_static` | Template analyzed (present or absent) |
| `runtime_advisory_join` | Runtime version identified and checked |

### Verdict Logic

| Scenario | Verdict | Exit Code |
|----------|---------|-----------|
| All core checks pass, no suspicious findings | SUITABLE | 0 |
| High-confidence suspicious finding | NOT SUITABLE | 1 |
| Medium-confidence suspicious finding | UNDETERMINED | 2 |
| Missing core check | UNDETERMINED | 2 |
| Error condition | UNDETERMINED | 2 |

### Why This Matters



This ensures that `SUITABLE` always means "we checked and found no issues," not "we didn't check."

## Finding Model

### Finding Dimensions

Each finding has three dimensions:

1. **Status**: What we found
2. **Severity**: How bad it is
3. **Confidence**: How sure we are

### Status Values

| Status | Meaning | Blocks Verdict? |
|--------|---------|-----------------|
| `verified` | Check passed with positive confirmation | No |
| `clean` | Check passed without suspicious findings | No |
| `suspicious` | Check found a confirmed risk | Yes (if high confidence) |
| `unchecked` | Check couldn't be completed | Yes (if core check) |
| `not_applicable` | Check doesn't apply | No |
| `error` | Check failed | Yes (if core check) |

### Severity Levels

| Severity | Meaning |
|----------|---------|
| `info` | Informational only |
| `low` | Minor concern |
| `medium` | Moderate concern |
| `high` | Serious concern |
| `critical` | Critical concern |

### Confidence Levels

| Confidence | Meaning |
|------------|---------|
| `low` | Low confidence in finding |
| `medium` | Medium confidence in finding |
| `high` | High confidence in finding |

## Common Findings

### GGUF Structure

| Finding | Meaning | Action |
|---------|---------|--------|
| `cbr.gguf.parsed` | GGUF parsed successfully | None needed |
| `cbr.gguf.inspection_error` | GGUF parsing failed | Check file integrity |
| `cbr.gguf.zero_dimension` | Tensor has zero-sized dimension | Re-convert model |

### Template Analysis

| Finding | Meaning | Action |
|---------|---------|--------|
| `cbr.template.static_clean` | Template parsed without issues | None needed |
| `cbr.template.constructs` | Template has risky constructs | Review manually |
| `cbr.template.poison.*` | Poison pattern detected | Do not load |
| `cbr.template.security.*` | Security pattern detected | Review manually |

### Companion Files

| Finding | Meaning | Action |
|---------|---------|--------|
| `cbr.config.no_signals` | No companion files found | None needed |
| `cbr.config.companion_security_*` | Security issue detected | Review manually |
| `cbr.config.rules_backdoor_*` | Rules File Backdoor detected | Do not load |

### Advisory Join

| Finding | Meaning | Action |
|---------|---------|--------|
| `cbr.join.CVE-*` | Advisory applies | Update runtime |
| `cbr.join.GGUF-*` | Advisory applies | Update runtime |

## Coverage

The coverage section shows what was and wasn't checked:

```
COVERAGE
  3 clean · 4 unchecked
```

- **clean**: Check passed without suspicious findings
- **unchecked**: Check couldn't be completed

### Interpreting Coverage

- **High coverage**: Most checks completed → more confidence in verdict
- **Low coverage**: Many checks incomplete → less confidence in verdict
- **Missing core checks**: Core checks incomplete → verdict is UNDETERMINED

## Limitations

The limitations section shows what Cancerbero couldn't check:

```
LIMITATIONS
  - Runtime version not provided; advisory join skipped.
  - Template reference not available; comparison skipped.
```

## Recommendations

Each suspicious finding includes an action recommendation:

```
Action: Do not load this model. The template contains patterns
consistent with a Poisoned GGUF Template attack. Obtain the model
from a trusted source with a verified template.
```

## Best Practices

### 1. Don't Just Look at the Verdict

Review all findings, especially:
- Suspicious findings
- Unchecked findings
- Error findings

### 2. Check Coverage

High coverage = more confidence in verdict.
Low coverage = review findings carefully.

### 3. Read Recommendations

Each suspicious finding includes an action recommendation.

### 4. Document Exceptions

If you accept a risk, document it:
- What risk was accepted
- Why it was accepted
- Who accepted it
- When it will be reviewed

### 5. Generate Reports for Auditing

```bash
# Timestamped reports
cancerbero check ./model.gguf --json "reports/$(date +%Y%m%d)-model-check.json"
```
