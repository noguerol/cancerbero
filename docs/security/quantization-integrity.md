# Quantization Integrity Verification

**Version:** 0.1.0  
**Status:** Implemented

## Overview

Cancerbero detects tensor misalignment in GGUF files, which can indicate corruption or malicious modification.

## Detection Philosophy

Cancerbero focuses on high-signal quantization issues:

- **Tensor misalignment:** Violates GGUF specification, may indicate corruption
- **Unknown quantization types:** May indicate custom or experimental types

## Attack Vectors Detected

### 1. Tensor Misalignment (Classification: HIGH)

**Research:** GGUF Specification, CVE-2026-27940

Tensor offsets must be multiples of the alignment value. Misalignment indicates corruption or malicious modification.

| Pattern | Description | Severity | Classification |
|---------|-------------|----------|----------------|
| `tensor_misalignment` | Tensor offset not aligned | HIGH | HIGH |

**Example:**
A tensor with offset 100 when alignment is 32 bytes indicates misalignment.

**Why it's dangerous:** 
- Violates the GGUF specification
- May indicate corruption or malicious modification
- Is a precondition for parser CVEs (CVE-2026-27940)

**References:**
- https://www.sentinelone.com/vulnerability-database/cve-2026-27940/
- GGUF Specification

### 2. Unknown Quantization Types (Classification: LOW)

**Research:** LLMQuA (ACM Web Conference 2026)

Tensors with unknown quantization types may be custom or experimental.

| Pattern | Description | Severity | Classification |
|---------|-------------|----------|----------------|
| `unknown_quant_type` | Unknown GGML tensor type | LOW | LOW |

**Example:**
A tensor using type 99 (not in the standard GGML_TYPE enum) may indicate a custom quantization scheme.

**Why it's concerning:** Unknown quantization types may be experimental or malicious.

**References:**
- https://dl.acm.org/doi/10.1145/3774904.3792256

## Removed Patterns (Previously Causing False Positives)

The following patterns were removed because they caused false positives:

| Pattern | Reason for Removal |
|---------|-------------------|
| `unusual_tensor_size` | Embedding tensors are always much larger than average |

## Usage

### Basic Usage

```bash
# Check a model for quantization integrity issues
cancerbero check ./model.gguf

# Check with verbose output
cancerbero check ./model.gguf --verbose

# Get JSON report
cancerbero check ./model.gguf --json report.json
```

### Interpreting Results

When quantization integrity issues are detected, the output includes:

```
FINDINGS
  ⚠ cbr.gguf.tensor_misalignment
    Tensor 'tensor.0' offset (100) is not aligned to 32 bytes.
    This violates the GGUF specification and may indicate corruption
    or malicious modification.
    
    Status: SUSPICIOUS | Severity: HIGH | Classification: HIGH
    
    Action: Do not load this model. The tensor alignment violates
    the GGUF specification. Re-obtain from a trusted source.
```

## False Positive Mitigation

### Conservative Patterns

Patterns are designed to minimize false positives:

- **Tensor misalignment:** Only flags when offset is not a multiple of alignment
- **Unknown types:** Only flags types not in the standard GGML_TYPE enum

### Removed Patterns

Patterns that caused false positives were removed:

- **Unusual tensor sizes:** Embedding tensors are always much larger than average

## References

### Primary Sources

1. **CVE-2026-27940 - Integer Overflow in GGUF Parser**
   - https://www.sentinelone.com/vulnerability-database/cve-2026-27940/
   - CVSS 7.8, heap out-of-bounds read and write

2. **LLMQuA - Backdoor Injection During Quantization**
   - https://dl.acm.org/doi/10.1145/3774904.3792256
   - ACM Web Conference 2026

3. **GGUF Specification**
   - https://github.com/ggml-org/llama.cpp/blob/master/gguf-spec.md
   - Official GGUF format specification

## Limitations

### What This Detection Can Do

- Detect tensor misalignment
- Detect unknown quantization types

### What This Detection Cannot Detect

- Sophisticated quantization-conditioned backdoors
- Runtime-only attacks
- Zero-day exploits
