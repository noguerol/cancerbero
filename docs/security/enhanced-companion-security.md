# Enhanced Companion File Security Analysis

**Version:** 0.1.0  
**Status:** Implemented

## Overview

Cancerbero detects security risks in files accompanying GGUF models. This analysis focuses on high-signal patterns that are definitively malicious or risky.

## Detection Philosophy

Cancerbero uses a conservative approach for companion file analysis:

- **High-signal only:** Only patterns that are definitively malicious or risky
- **No false positives:** Patterns that fire on legitimate files are removed
- **Actionable findings:** Each finding has a clear recommended action

## Attack Vectors Detected

### 1. Hardcoded Credentials (Classification: HIGH)

**Research:** CSA Research Note, BeyondScale

Hardcoded credentials in configuration files are a critical security risk.

| Pattern | Description | Severity | Classification |
|---------|-------------|----------|----------------|
| `hardcoded_api_key` | API keys and tokens | HIGH | HIGH |
| `hardcoded_aws_credentials` | AWS credentials | HIGH | HIGH |
| `hardcoded_private_key` | Private keys | HIGH | HIGH |
| `hardcoded_password` | Passwords | HIGH | HIGH |

**Example:**
```json
{
  "api_key": "sk-1234567890abcdef1234567890abcdef"
}
```

**Why it's dangerous:** Exposed credentials can be used for unauthorized access, data exfiltration, or financial damage.

**References:**
- https://labs.cloudsecurityalliance.org/research/csa-research-note-model-poisoning-self-hosted-llm-stealer-20/

### 2. Remote Code Execution (Classification: HIGH)

**Research:** OWASP LLM01:2025, Hugging Face security

Configuration files that enable remote code execution.

| Pattern | Description | Severity | Classification |
|---------|-------------|----------|----------------|
| `trust_remote_code_enabled` | trust_remote_code flag | HIGH | HIGH |
| `auto_map_config` | auto_map configuration | HIGH | HIGH |
| `remote_from_url` | Remote URLs in Modelfile | HIGH | HIGH |

**Example:**
```json
{
  "trust_remote_code": true
}
```

**Why it's dangerous:** trust_remote_code allows executing code from remote repositories during model loading.

**References:**
- https://huggingface.co/blog/huseyingulsin/ai-for-organizations-2-risk-of-pickle

### 3. Network Exfiltration (Classification: HIGH)

**Research:** Vectra AI, OWASP LLM01:2025

Configuration files with URLs used for data exfiltration.

| Pattern | Description | Severity | Classification |
|---------|-------------|----------|----------------|
| `discord_slack_webhook` | Discord/Slack webhooks | HIGH | HIGH |
| `data_exfiltration_url` | URLs with data params | HIGH | HIGH |

**Example:**
```json
{
  "notify": "https://discord.com/api/webhooks/123456/abcdef"
}
```

**Why it's dangerous:** Webhook URLs can be used to exfiltrate sensitive data from the system.

**References:**
- https://www.vectra.ai/topics/prompt-injection

## Usage

### Basic Usage

```bash
# Check a model for companion file security issues
cancerbero check ./model.gguf

# Check with verbose output
cancerbero check ./model.gguf --verbose

# Get JSON report
cancerbero check ./model.gguf --json report.json
```

### Interpreting Results

When companion file security issues are detected, the output includes:

```
FINDINGS
  ⚠ cbr.config.companion_security_hardcoded_api_key.0
    File contains hardcoded API keys or tokens. These should be stored
    in environment variables or secure vaults.
    
    Status: SUSPICIOUS | Severity: HIGH | Classification: HIGH
    
    Action: Remove hardcoded credentials and use environment variables.
```

## False Positive Mitigation

### Conservative Patterns

Patterns are designed to minimize false positives:

- **Hardcoded credentials:** Only matches high-entropy strings that look like real credentials
- **Remote code execution:** Only matches explicit trust_remote_code settings
- **Network exfiltration:** Only matches Discord/Slack webhooks and URLs with data parameters

### Removed Patterns (Previously Causing False Positives)

The following patterns were removed because they caused false positives on legitimate files:

| Pattern | Reason for Removal |
|---------|-------------------|
| `pickle_deserialization` | Fires on any Python file with `import pickle` |
| `mcp_server_config` | Fires on user's own MCP configuration |
| `custom_tokenizer` | Fires on standard tokenizer classes |
| `webhook_endpoint` | Fires on legitimate webhook configurations |

## References

### Primary Sources

1. **CSA - Model Poisoning Credential Exfiltration**
   - https://labs.cloudsecurityalliance.org/research/csa-research-note-model-poisoning-self-hosted-llm-stealer-20/
   - Credential exfiltration in self-hosted LLM deployments

2. **BeyondScale - Open Source AI Model Security**
   - https://beyondscale.tech/blog/open-source-ai-model-security-hugging-face
   - Vetting Hugging Face downloads

3. **OWASP Top 10 for LLM Applications 2025**
   - https://owasp.org/Top10/LLM01_2025-Prompt_Injection/
   - Prompt injection vulnerabilities

4. **Vectra AI - Prompt Injection**
   - https://www.vectra.ai/topics/prompt-injection
   - Real-world CVEs and attack patterns

## Limitations

### What This Detection Can Do

- Detect hardcoded credentials
- Detect remote code execution configurations
- Detect network exfiltration patterns

### What This Detection Cannot Detect

- Novel, unknown attack patterns
- Obfuscated malicious code
- Runtime-only attacks
- Attacks that use legitimate features
