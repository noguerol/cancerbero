# Security Documentation

Welcome to Cancerbero's security documentation. This section covers the threat model, attack vectors, and detection capabilities.

## Overview

Cancerbero is a security inspection tool for GGUF models and llama.cpp runtimes. It detects known vulnerabilities, suspicious patterns, and attack vectors in model artifacts before they reach your runtime.

## Documentation Index

### Threat Model
- [Threat Model](threat-model.md) — What Cancerbero protects against
- [Attack Surface](threat-model.md#attack-surface-overview) — Overview of the model supply chain

### Attack Vectors
- [Poisoned GGUF Templates](poisoned-templates.md) — Inference-time backdoor detection
- [Rules File Backdoor](rules-file-backdoor.md) — Companion file injection detection
- [Hugging Face UI Blindspot](hf-ui-blindspot.md) — Multi-file template mismatch detection
- [Enhanced Template Security](enhanced-template-security.md) — Dangerous functions, exfiltration, encoded instructions
- [Enhanced Companion Security](enhanced-companion-security.md) — Hardcoded credentials, remote code execution, network exfiltration
- [Model Card Analysis](model-card-analysis.md) — Credential harvesting, shortened URLs
- [Quantization Integrity](quantization-integrity.md) — Tensor misalignment detection
- [Runtime Configuration Security](runtime-config-security.md) — Network exposure, API key in args
- [Supply Chain Verification](supply-chain-verification.md) — Impossible quantization, suspicious file types

### Advisory Database
- [Advisory Database](advisories.md) — Known vulnerabilities and CVEs
- [Advisory Sources](advisories.md#references) — Primary sources and verification

### Detection Capabilities
- [Template Analysis](poisoned-templates.md#cancerbero-detection) — Static template analysis
- [Companion File Inspection](rules-file-backdoor.md#cancerbero-detection) — Rules File Backdoor detection
- [Advisory Join](advisories.md#how-advisory-join-works) — Runtime vulnerability matching

## Quick Reference

### What Cancerbero Detects

| Attack Vector | Detection | Status |
|---------------|-----------|--------|
| Poisoned GGUF Templates | Pattern matching | ✅ Implemented |
| Rules File Backdoor | Pattern matching | ✅ Implemented |
| HF UI Blindspot | Template comparison | ✅ Implemented |
| Known CVEs | Advisory join | ✅ Implemented |
| Structural issues | GGUF parsing | ✅ Implemented |
| Hardcoded credentials | Pattern matching | ✅ Implemented |
| Remote code execution | Pattern matching | ✅ Implemented |
| Network exfiltration | Pattern matching | ✅ Implemented |
| Tensor misalignment | GGUF validation | ✅ Implemented |
| Network exposure | Flag analysis | ✅ Implemented |

### What Cancerbero Doesn't Detect

| Threat | Reason |
|--------|--------|
| Backdoors in weights | Requires ML frameworks |
| Novel vulnerabilities | Unknown at inspection time |
| Runtime behavior | Static analysis only |
| Zero-day exploits | No signature available |

## Verdict Policy

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

If any core check is missing, the verdict is UNDETERMINED.

## Getting Started

### 1. Understand the Threat Model

Read the [Threat Model](threat-model.md) to understand:
- What Cancerbero protects against
- What it doesn't protect against
- How it fits into defense-in-depth

### 2. Learn About Attack Vectors

Read about specific attack vectors:
- [Poisoned GGUF Templates](poisoned-templates.md) — The most critical threat
- [Rules File Backdoor](rules-file-backdoor.md) — Companion file risks
- [Enhanced Template Security](enhanced-template-security.md) — Dangerous functions, exfiltration
- [Enhanced Companion Security](enhanced-companion-security.md) — Hardcoded credentials, RCE

### 3. Check the Advisory Database

Review the [Advisory Database](advisories.md) to understand:
- Known vulnerabilities
- Version boundaries
- How advisories are matched

### 4. Use Cancerbero

```bash
# Basic check (requires runtime for SUITABLE verdict)
cancerbero check ./model.gguf --runtime ./llama-cli --runtime-version b8146

# Directory scan
cancerbero check ./models/
```

## Key Concepts

### Defense in Depth

Cancerbero is one layer in a defense-in-depth strategy:

| Layer | Tool | Purpose |
|-------|------|---------|
| **Pre-deployment** | Cancerbero | Static inspection |
| **Runtime** | llama.cpp updates | Patch vulnerabilities |
| **Monitoring** | Guardrails | Detect anomalies |
| **Response** | Incident response | Handle incidents |

### Static Analysis

Cancerbero uses static analysis (no model execution) because:

1. **Safety**: Executing untrusted models is risky
2. **Speed**: Static analysis is fast
3. **Determinism**: Same input → same output
4. **Scope**: Checks what's verifiable without execution

### Honest Coverage

Cancerbero reports what it can and cannot check:

- **Verified**: Check passed with positive confirmation
- **Clean**: Check passed without suspicious findings
- **Suspicious**: Check found a confirmed risk
- **Unchecked**: Check couldn't be completed
- **Not Applicable**: Check doesn't apply
- **Error**: Check failed

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

### 4. Review All Findings

Don't just look at the verdict. Review:
- All findings (especially unchecked)
- Coverage summary
- Error messages
- Recommendations

### 5. Document Exceptions

If you accept a risk, document it:
- What risk was accepted
- Why it was accepted
- Who accepted it
- When it will be reviewed

## Contributing

### Reporting Vulnerabilities

If you discover a vulnerability in Cancerbero itself:
1. Report privately to repository maintainers
2. See [SECURITY.md](../../SECURITY.md) for details

### Adding Advisories

To add advisories to Cancerbero:
1. Verify against primary sources
2. Include source URL and dates
3. Define version boundaries
4. Submit pull request

### Improving Detection

To improve Cancerbero's detection:
1. Identify new attack vectors
2. Define detection patterns
3. Add tests
4. Submit pull request

## References

### External Resources

- [Pillar Security Research](https://www.pillar.security/blog)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NIST AI Risk Management Framework](https://www.nist.gov/artificial-intelligence)
- [GitHub Security Advisories](https://github.com/ggml-org/llama.cpp/security/advisories)

### Cancerbero Documentation

- [CLI Reference](../reference/cli.md)
- [Output Formats](../reference/output-formats.md)
- [Finding Model](../reference/findings.md)
- [Exit Codes](../reference/exit-codes.md)
- [Configuration](../reference/config-file.md)
