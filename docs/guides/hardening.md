# Configuration Hardening Recommendations

**Version:** 0.1.0  
**Date:** 2026-08-28  
**Status:** Implemented

## Overview

Cancerbero generates actionable security hardening recommendations based on findings from all inspection phases. These recommendations help users secure their llama.cpp deployments.

## Recommendation Categories

### Runtime Recommendations

| Priority | Title | Description |
|----------|-------|-------------|
| **Critical** | Update llama.cpp | Update to latest version to patch vulnerabilities |
| **Medium** | Provide runtime version | Use --runtime-version for accurate checks |

### Network Recommendations

| Priority | Title | Description |
|----------|-------|-------------|
| **High** | Restrict network access | Use --host 127.0.0.1 instead of 0.0.0.0 |
| **High** | Use environment variables | Use env vars for API keys, not command-line args |

### Template Recommendations

| Priority | Title | Description |
|----------|-------|-------------|
| **Critical** | Don't load suspicious templates | Templates with attack patterns should not be loaded |
| **Medium** | Review extraction attempts | Templates with extraction patterns need review |

### Companion File Recommendations

| Priority | Title | Description |
|----------|-------|-------------|
| **Critical** | Remove pickle dependencies | Replace pickle with safetensors |
| **Critical** | Remove hardcoded credentials | Use environment variables |
| **High** | Disable trust_remote_code | Set trust_remote_code: false |

### Supply Chain Recommendations

| Priority | Title | Description |
|----------|-------|-------------|
| **High** | Verify model source | Check suspicious models carefully |
| **Medium** | Verify uncensored models | Check legitimacy of uncensored claims |

### General Recommendations

| Priority | Title | Description |
|----------|-------|-------------|
| **Medium** | Prefer safetensors format | Safer than pickle-based formats |
| **Low** | Always check before loading | Run Cancerbero before loading models |
| **Low** | Keep Cancerbero updated | Update for latest advisories |

## Usage

### Viewing Recommendations

```bash
# Recommendations are shown in terminal output
cancerbero check ./model.gguf

# Verbose mode shows all recommendations
cancerbero check ./model.gguf --verbose

# JSON output includes recommendations
cancerbero check ./model.gguf --json report.json
```

### Example Output

```
💡 RECOMMENDATIONS
  [CRITICAL] Update llama.cpp to latest version
    Your llama.cpp installation has known vulnerabilities.
    Update to the latest version to patch security issues.
    → Run: git pull && make clean && make

  [HIGH] Restrict network access
    Your runtime is configured to accept network connections.
    Restrict access to localhost or use a firewall.
    → Use --host 127.0.0.1 instead of --host 0.0.0.0

  [MEDIUM] Prefer safetensors format
    Safetensors is a safer alternative to pickle-based formats.
    Prefer models in safetensors format when available.
    → Convert models to safetensors format when possible.
```

## Best Practices

### 1. Always Provide Runtime Version

```bash
# Good: Provides runtime for accurate checks
cancerbero check ./model.gguf --runtime ./llama-cli --runtime-version b8146

# Bad: No runtime, recommendations may be incomplete
cancerbero check ./model.gguf
```

### 2. Review Critical Recommendations

Critical recommendations indicate security vulnerabilities that should be addressed immediately:

- **Update llama.cpp**: Patch known vulnerabilities
- **Remove pickle dependencies**: Replace with safetensors
- **Remove hardcoded credentials**: Use environment variables

### 3. Implement High Recommendations

High recommendations indicate significant security risks:

- **Restrict network access**: Use localhost binding
- **Use environment variables**: For API keys and credentials
- **Disable trust_remote_code**: Unless explicitly needed

### 4. Consider Medium Recommendations

Medium recommendations indicate potential security improvements:

- **Prefer safetensors format**: Safer than pickle
- **Review extraction attempts**: In templates
- **Verify uncensored models**: Check legitimacy

### 5. Optional Low Recommendations

Low recommendations are best practices:

- **Always check before loading**: Run Cancerbero first
- **Keep Cancerbero updated**: For latest advisories

## References

### Primary Sources

1. **Tech Insider - llama.cpp Tutorial 2026**
   - https://tech-insider.org/llama-cpp-tutorial-2026/
   - Production hardening tips

2. **Hyperion Consulting - Ollama Enterprise Deployment Guide 2026**
   - https://hyperion-consulting.io/en/insights/ollama-enterprise-deployment-guide-2026
   - Enterprise security best practices

3. **SitePoint - Local LLM Security Best Practices 2026**
   - https://www.sitepoint.com/local-llm-security-best-practices-2026/
   - Container security, encrypted storage

4. **Medium - 4 llama.cpp Settings That Matter**
   - https://xhinker.medium.com/4-llama-cpp-settings-that-matter-but-nobody-talks-about-22bf763f8615
   - Important but overlooked settings

5. **SentinelOne - CVE-2026-27940 Analysis**
   - https://www.sentinelone.com/vulnerability-database/cve-2026-27940/
   - Update recommendations

6. **daily.dev - Running LLMs Locally in 2026**
   - https://daily.dev/blog/running-llms-locally-ollama-llama-cpp-self-hosted-ai-developers/
   - Privacy and security considerations
