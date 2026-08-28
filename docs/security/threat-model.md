# Threat Model

Cancerbero defends against attacks on the AI model supply chain, specifically targeting GGUF models and their deployment through llama.cpp.

## Attack Surface Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    MODEL SUPPLY CHAIN                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │  Model   │───▶│ Download │───▶│  Local   │              │
│  │ Creator  │    │ Platform │    │ Storage  │              │
│  └──────────┘    └──────────┘    └──────────┘              │
│       │               │               │                     │
│       ▼               ▼               ▼                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ Template │    │  UI      │    │Companion │              │
│  │ Injection│    │ Blindspot│    │  Files   │              │
│  └──────────┘    └──────────┘    └──────────┘              │
│       │               │               │                     │
│       └───────────────┼───────────────┘                     │
│                       ▼                                     │
│              ┌──────────────────┐                           │
│              │   Cancerbero     │ ◀── YOU ARE HERE          │
│              │   Inspection     │                           │
│              └──────────────────┘                           │
│                       │                                     │
│                       ▼                                     │
│              ┌──────────────────┐                           │
│              │    llama.cpp     │                           │
│              │    Runtime       │                           │
│              └──────────────────┘                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Threat Actors

### 1. Malicious Model Uploaders

**Motivation**: Compromise downstream users, steal credentials, exfiltrate data

**Capabilities**:
- Modify chat templates in GGUF files
- Create multiple quantized variants with different templates
- Upload to public repositories (Hugging Face, Ollama Registry)

**Detection**: Poisoned Template Detection, HF UI Blindspot Detection

### 2. Supply Chain Attackers

**Motivation**: Wide-scale compromise through trusted distribution channels

**Capabilities**:
- Compromise model repositories
- Inject malicious companion files
- Modify model metadata

**Detection**: Rules File Backdoor Detection, Companion File Inspection

### 3. Insider Threats

**Motivation**: Data exfiltration, sabotage, unauthorized access

**Capabilities**:
- Modify models in internal repositories
- Inject malicious configurations
- Tamper with model provenance

**Detection**: Digest Verification, Manifest Coherence Checking

## Attack Vectors

### Vector 1: Poisoned GGUF Templates

**Description**: Malicious instructions embedded in `tokenizer.chat_template` that execute during inference.

**Impact**: 
- Data exfiltration to attacker-controlled endpoints
- Credential harvesting
- Model behavior manipulation
- Bypass of input/output guardrails

**Detection**: Cancerbero

**Details**: [Poisoned Templates Guide](poisoned-templates.md)

### Vector 2: Rules File Backdoor

**Description**: Malicious instructions in companion files (README, config, rules) that AI tools consume.

**Impact**:
- Code injection in AI-assisted development
- Credential theft through AI code editors
- Supply chain compromise of development tools

**Detection**: Cancerbero

**Details**: [Rules File Backdoor Guide](rules-file-backdoor.md)

### Vector 3: Hugging Face UI Blindspot

**Description**: Different templates across GGUF files in same repository; UI shows only first file's template.

**Impact**:
- Users review clean template but download malicious variant
- Security scanners miss per-file template differences
- False sense of security

**Detection**: Cancerbero

**Details**: [HF UI Blindspot Guide](hf-ui-blindspot.md)

### Vector 4: Runtime Vulnerabilities

**Description**: Known vulnerabilities in llama.cpp that can be exploited by crafted GGUF files.

**Impact**:
- Heap buffer overflows
- Out-of-bounds reads/writes
- Potential remote code execution

**Detection**: Cancerbero v0.1.0+ (Advisory Join)

**Details**: [Advisory Database](advisories.md)

### Vector 5: Template Injection (llama-cpp-python)

**Description**: Unsafe template rendering in llama-cpp-python versions 0.2.30–0.2.71.

**Impact**:
- Server-side template injection
- Arbitrary code execution during inference

**Detection**: Cancerbero (Advisory Join)

## What Cancerbero Does NOT Detect

Cancerbero is designed for specific, verifiable checks. It does **not**:

1. **Detect backdoors in model weights** — Weight analysis requires ML frameworks and is out of scope
2. **Prove absence of malicious behavior** — Only positive findings are reported
3. **Certify models as "safe"** — There is no binary safety verdict
4. **Execute models or templates** — Static analysis only in default path
5. **Monitor runtime behavior** — Cancerbero is a pre-deployment tool

## Defense in Depth

Cancerbero is one layer in a defense-in-depth strategy:

| Layer | Tool | Purpose |
|-------|------|---------|
| **Pre-deployment** | Cancerbero | Static inspection of artifacts |
| **Runtime** | llama.cpp updates | Patch known vulnerabilities |
| **Monitoring** | Runtime guardrails | Detect anomalous behavior |
| **Response** | Incident response | Handle compromised deployments |

## Reporting Vulnerabilities

If you discover a vulnerability in Cancerbero itself, please report it privately to the repository maintainers. See [SECURITY.md](../../SECURITY.md) for details.

## References

- [Pillar Security Research](https://www.pillar.security/blog)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NIST AI Risk Management Framework](https://www.nist.gov/artificial-intelligence)
