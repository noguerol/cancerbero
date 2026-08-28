# Supply Chain Verification

**Version:** 0.1.0  
**Status:** Implemented

## Overview

Cancerbero detects supply chain risks in model artifacts before loading them. This analysis focuses on high-signal patterns that are definitively malicious.

## Detection Philosophy

Cancerbero uses a conservative approach for supply chain verification:

- **High-signal only:** Only patterns that are definitively malicious
- **No content judgment:** "Uncensored" models are not inherently malicious
- **No name matching:** Legitimate model names are not suspicious

## Attack Vectors Detected

### 1. Impossible Quantization (Classification: HIGH)

**Research:** BeyondScale

Models claiming impossible quantization types may be fake or malicious.

| Pattern | Description | Severity | Classification |
|---------|-------------|----------|----------------|
| `impossible_quantization` | Impossible quantization type | HIGH | HIGH |

**Example:**
```
model-Q0_0.gguf  # Q0_0 doesn't exist
```

**Why it's dangerous:** Fake quantization claims may indicate a malicious model disguised as a legitimate one.

**References:**
- https://beyondscale.tech/blog/open-source-ai-model-security-hugging-face

### 2. Suspicious File Types (Classification: HIGH)

**Research:** JFrog, ReversingLabs

Models with suspicious file extensions may be malicious files disguised as models.

| Pattern | Description | Severity | Classification |
|---------|-------------|----------|----------------|
| `suspicious_file_type` | Suspicious file extension | HIGH | HIGH |

**Example:**
```
model.exe  # Not a model file
model.py   # Not a model file
```

**Why it's dangerous:** Malicious files may be disguised as models to trick users into executing them.

**References:**
- https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face
- https://jfrog.com/blog/unveiling-3-zero-day-vulnerabilities-in-picklescan/

## Removed Patterns (Previously Causing False Positives)

The following patterns were removed because they caused false positives:

| Pattern | Reason for Removal |
|---------|-------------------|
| `popular_model_name` | Fires on legitimate models with popular names |
| `suspicious_uploader` | Legal risk, easy to evade |
| `uncensored_model` | Content judgment, not security |

## Usage

### Basic Usage

```bash
# Check a model for supply chain issues
cancerbero check ./model.gguf

# Check with verbose output
cancerbero check ./model.gguf --verbose

# Get JSON report
cancerbero check ./model.gguf --json report.json
```

### Interpreting Results

When supply chain issues are detected, the output includes:

```
FINDINGS
  ⚠ cbr.supply_chain.impossible_quantization
    Model claims impossible quantization type. This may be a fake
    or malicious model.
    
    Status: SUSPICIOUS | Severity: HIGH | Classification: HIGH
    
    Action: Verify the model is from a legitimate source.
```

## False Positive Mitigation

### Conservative Patterns

Patterns are designed to minimize false positives:

- **Impossible quantization:** Only flags quantization types that don't exist
- **Suspicious file types:** Only flags executable extensions

### Removed Patterns

Patterns that caused false positives were removed:

- **Popular model names:** Fires on legitimate models
- **Suspicious uploaders:** Legal risk, easy to evade
- **Uncensored models:** Content judgment, not security

## References

### Primary Sources

1. **BeyondScale - Open Source AI Model Security**
   - https://beyondscale.tech/blog/open-source-ai-model-security-hugging-face
   - Vetting Hugging Face downloads

2. **ReversingLabs - nullifAI Technique**
   - https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face
   - Novel attack technique on Hugging Face

3. **JFrog - PickleScan Vulnerabilities**
   - https://jfrog.com/blog/unveiling-3-zero-day-vulnerabilities-in-picklescan/
   - Three critical zero-day vulnerabilities

## Limitations

### What This Detection Can Do

- Detect impossible quantization types
- Detect suspicious file types

### What This Detection Cannot Detect

- Novel, unknown attack patterns
- Sophisticated typosquatting
- Zero-day exploits
- Attacks that use legitimate features
