# Model Card and Documentation Analysis

**Version:** 0.1.0  
**Status:** Implemented

## Overview

Cancerbero detects high-signal malicious patterns in model documentation. This analysis focuses on patterns that are definitively malicious, not governance issues.

## Detection Philosophy

Cancerbero uses a conservative approach for model card analysis:

- **High-signal only:** Only patterns that are definitively malicious
- **No governance issues:** License, training data, etc. are not security concerns
- **No content judgment:** "Uncensored" models are not inherently malicious

## Attack Vectors Detected

### 1. Credential Harvesting (Classification: HIGH)

**Research:** Hive Security, ReversingLabs

Documentation that instructs users to exfiltrate credentials.

| Pattern | Description | Severity | Classification |
|---------|-------------|----------|----------------|
| `credential_harvest_doc` | Instructions to exfiltrate credentials | HIGH | HIGH |

**Example:**
```markdown
# Model

Please send your API key to activate this model.
```

**Why it's dangerous:** This is a known attack pattern to steal credentials.

**References:**
- https://hivesecurity.gitlab.io/blog/huggingface-ai-supply-chain-attacks-2026/
- https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face

### 2. Shortened URLs (Classification: HIGH)

**Research:** BeyondScale

Documentation with shortened URLs that can hide malicious destinations.

| Pattern | Description | Severity | Classification |
|---------|-------------|----------|----------------|
| `suspicious_shortened_url` | Shortened URLs | HIGH | HIGH |

**Example:**
```markdown
# Model

Download from https://bit.ly/evil-model
```

**Why it's dangerous:** Shortened URLs can hide malicious destinations.

**References:**
- https://beyondscale.tech/blog/open-source-ai-model-security-hugging-face

## Removed Patterns (Previously Causing False Positives)

The following patterns were removed because they caused false positives on legitimate model cards:

| Pattern | Reason for Removal |
|---------|-------------------|
| `suspicious_claim_uncensored` | Legitimate research models |
| `suspicious_claim_perfect` | Marketing, not security |
| `suspicious_claim_bypass` | Legitimate red-teaming models |
| `missing_license` | Governance, not security |
| `missing_training_data` | Governance, not security |
| `untrusted_code_instruction` | Fires on any `pip install` |
| `personal_info_request` | Legitimate gated models |

## Usage

### Basic Usage

```bash
# Check a model for documentation issues
cancerbero check ./model.gguf

# Check with verbose output
cancerbero check ./model.gguf --verbose

# Get JSON report
cancerbero check ./model.gguf --json report.json
```

### Interpreting Results

When documentation issues are detected, the output includes:

```
FINDINGS
  ⚠ cbr.config.model_card_credential_harvest_doc.0
    Documentation contains instructions to exfiltrate credentials.
    This is a known attack pattern.
    
    Status: SUSPICIOUS | Severity: HIGH | Classification: HIGH
    
    Action: Review the documentation carefully. Credential harvesting
    is a known attack pattern.
```

## False Positive Mitigation

### Conservative Patterns

Patterns are designed to minimize false positives:

- **Credential harvesting:** Only matches explicit instructions to send credentials
- **Shortened URLs:** Only matches known URL shorteners

### Removed Patterns

Patterns that caused false positives on legitimate model cards were removed:

- **Uncensored claims:** Legitimate for research models
- **Perfect claims:** Marketing, not security
- **Missing information:** Governance, not security
- **Untrusted code:** Fires on any `pip install`

## References

### Primary Sources

1. **Hive Security - Hugging Face Supply Chain Attacks**
   - https://hivesecurity.gitlab.io/blog/huggingface-ai-supply-chain-attacks-2026
   - Open-OSS/privacy-filter incident with 244,000 downloads

2. **ReversingLabs - nullifAI Technique**
   - https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face
   - Novel attack technique on Hugging Face

3. **BeyondScale - Open Source AI Model Security**
   - https://beyondscale.tech/blog/open-source-ai-model-security-hugging-face
   - Vetting Hugging Face downloads

## Limitations

### What This Detection Can Do

- Detect credential harvesting attempts
- Detect shortened URLs

### What This Detection Cannot Detect

- Novel, unknown attack patterns
- Obfuscated malicious content
- Runtime-only attacks
- Attacks that use legitimate features
