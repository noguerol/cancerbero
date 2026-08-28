# Runtime Configuration Security Analysis

**Version:** 0.1.0  
**Status:** Implemented

## Overview

Cancerbero detects security issues in llama.cpp runtime configuration that expose the server to network attacks or credential theft.

## Detection Philosophy

Cancerbero focuses on high-signal runtime configuration issues:

- **Network exposure:** Binding to all interfaces exposes the server
- **Credential exposure:** API keys in command-line arguments can be exposed

## Attack Vectors Detected

### 1. Network Exposure (Classification: HIGH)

**Research:** CVE-2026-21869, TheHackerWire

Runtime configuration that exposes the server to the network.

| Pattern | Description | Severity | Classification |
|---------|-------------|----------|----------------|
| `bind_all_interfaces` | Binds to 0.0.0.0 | HIGH | HIGH |

**Example:**
```bash
llama-server --model ./model.gguf --host 0.0.0.0 --port 8080
```

**Why it's dangerous:** Binding to all interfaces exposes the server to network attacks.

**References:**
- https://www.thehackerwire.com/llama-cpp-server-rce-negative-parameter-triggers-oob-write/
- https://cve.akaoma.com/cve-2026-21869

### 2. Credential Exposure (Classification: HIGH)

**Research:** Tech Insider, llama.cpp best practices

API keys in command-line arguments can be exposed in process listings.

| Pattern | Description | Severity | Classification |
|---------|-------------|----------|----------------|
| `api_key_in_args` | API key in command line | HIGH | HIGH |

**Example:**
```bash
llama-server --model ./model.gguf --api-key sk-1234567890abcdef
```

**Why it's dangerous:** API keys in command-line arguments can be exposed in process listings.

**References:**
- https://tech-insider.org/llama-cpp-tutorial-2026/

## Removed Patterns (Previously Causing False Positives)

The following patterns were removed because they are performance flags, not security issues:

| Pattern | Reason for Removal |
|---------|-------------------|
| `no_mmap` | Performance flag, not security |
| `mlock` | Recommended by llama.cpp |
| `no_numa` | Performance flag, not security |
| `cont_batching` | Performance flag, not security |
| `no_warmup` | Performance flag, not security |
| `allow_spawn` | Not a real llama.cpp flag |
| `network_port` | Listening on a port is normal |
| `disable_escape` | Not a real security issue |

## Usage

### Basic Usage

```bash
# Check a model for runtime configuration issues
cancerbero check ./model.gguf

# Check with verbose output
cancerbero check ./model.gguf --verbose

# Get JSON report
cancerbero check ./model.gguf --json report.json
```

### Interpreting Results

When runtime configuration issues are detected, the output includes:

```
FINDINGS
  ⚠ cbr.runtime_config.bind_all_interfaces
    Runtime binds to all network interfaces. This exposes the server
    to the network. Use --host 127.0.0.1 to restrict to localhost.
    
    Status: SUSPICIOUS | Severity: HIGH | Classification: HIGH
    
    Action: Use --host 127.0.0.1 instead of --host 0.0.0.0.
```

## False Positive Mitigation

### Conservative Patterns

Patterns are designed to minimize false positives:

- **Network exposure:** Only flags binding to 0.0.0.0
- **Credential exposure:** Only flags explicit API key arguments

### Removed Patterns

Patterns that caused false positives were removed:

- **Performance flags:** --no-mmap, --mlock, --no-numa, etc.
- **Non-existent flags:** --allow-spawn
- **Normal behavior:** Listening on a port

## References

### Primary Sources

1. **CVE-2026-21869 - Negative Parameter OOB Write**
   - https://cve.akaoma.com/cve-2026-21869
   - RCE via negative n_discard parameter

2. **TheHackerWire - llama.cpp Server RCE**
   - https://www.thehackerwire.com/llama-cpp-server-rce-negative-parameter-triggers-oob-write/

3. **Tech Insider - llama.cpp Tutorial 2026**
   - https://tech-insider.org/llama-cpp-tutorial-2026/
   - Production hardening tips

## Limitations

### What This Detection Can Do

- Detect network exposure
- Detect credential exposure

### What This Detection Cannot Detect

- Novel, unknown vulnerabilities
- Runtime-only attacks
- Zero-day exploits
