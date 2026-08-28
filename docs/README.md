# Cancerbero Documentation

> **Cancerbero** — The three-headed guardian for your AI model supply chain.

Welcome to the official documentation for Cancerbero, a local-first security inspection tool for GGUF models and llama.cpp runtimes.

## Quick Navigation

### Getting Started
- [Installation Guide](guides/installation.md) — Get Cancerbero running in minutes
- [Quick Start](guides/quickstart.md) — Your first model inspection
- [Configuration](guides/configuration.md) — Customize Cancerbero for your workflow

### Core Concepts
- [How Cancerbero Works](guides/how-it-works.md) — Architecture and inspection pipeline
- [Understanding Reports](guides/reports.md) — Interpreting findings and verdicts
- [Exit Codes](reference/exit-codes.md) — Automation and CI/CD integration

### Security & Attack Detection
- [Threat Model](security/threat-model.md) — What Cancerbero protects against
- [Poisoned GGUF Templates](security/poisoned-templates.md) — Inference-time backdoor detection
- [Rules File Backdoor](security/rules-file-backdoor.md) — Companion file injection detection
- [Hugging Face UI Blindspot](security/hf-ui-blindspot.md) — Multi-file template mismatch detection
- [Enhanced Template Security](security/enhanced-template-security.md) — Dangerous functions, exfiltration, encoded instructions
- [Enhanced Companion Security](security/enhanced-companion-security.md) — Pickle deserialization, MCP servers, hardcoded credentials
- [Model Card Analysis](security/model-card-analysis.md) — Suspicious claims, missing information, malicious patterns
- [Quantization Integrity](security/quantization-integrity.md) — Unknown types, unusual sizes, misalignment
- [Runtime Configuration Security](security/runtime-config-security.md) — Dangerous flags, network exposure, sandboxing
- [Supply Chain Verification](security/supply-chain-verification.md) — Typosquatting, suspicious uploaders, fake quantization

- [Advisory Database](security/advisories.md) — Known vulnerabilities and CVEs

### Reference
- [CLI Reference](reference/cli.md) — Complete command-line documentation
- [Output Formats](reference/output-formats.md) — Terminal, JSON, Markdown, SARIF
- [Finding Model](reference/findings.md) — Status, severity, confidence explained
- [Configuration File](reference/config-file.md) — cancerbero.yaml reference
- [Exit Codes](reference/exit-codes.md) — Exit code policy

### Advanced Topics
- [CI/CD Integration](guides/cicd.md) — GitHub Actions, GitLab CI, Jenkins
- [Batch Processing](guides/batch.md) — Checking multiple models efficiently
- [Custom Advisory Rules](guides/custom-advisories.md) — Extending the knowledge bundle
- [Third-Party Delegates](guides/delegates.md) — ModelAudit, PickleScan, Fickling, ModelScan
- [Hardening Recommendations](guides/hardening.md) — Security best practices
- [Troubleshooting](guides/troubleshooting.md) — Common issues and solutions

## About Cancerbero

### The Problem

As AI models become critical infrastructure, the supply chain that delivers them becomes a target. Attackers can:

- Embed malicious instructions in chat templates that execute during inference
- Hide backdoors in quantized model variants while showing clean templates on repositories
- Inject malicious code into companion files that AI tools consume
- Exploit vulnerabilities in model parsers and runtimes

Traditional security scanners focus on model weights and infrastructure threats, missing the critical layer between input validation and model output: **the template and configuration layer**.

### The Solution

Cancerbero inspects GGUF artifacts **before** they reach your runtime, answering three questions:

1. **Provenance** — Is this artifact what it claims to be?
2. **Loading** — What risks does it introduce when loaded in this specific runtime?
3. **Behavior** — Does its template or configuration contain suspicious patterns?

### Design Principles

- **Local-first**: No network access, no telemetry, no data leaves your machine
- **Offline-capable**: Works completely offline with embedded knowledge bundle
- **No ML frameworks**: Only Jinja2 dependency; no PyTorch, Transformers, or TensorFlow
- **Honest coverage**: Missing checks are reported as "unchecked," never hidden
- **No safety seals**: Findings are evidence-based, not binary pass/fail scores

### Verdict Policy

Cancerbero requires **positive evidence from core checks** before producing a `SUITABLE` verdict. The core checks are:

1. **gguf_structure** — GGUF parsed successfully
2. **chat_template_static** — Template analyzed (present or absent)
3. **runtime_advisory_join** — Runtime version identified and checked

If any core check is missing (unchecked/error), the verdict is `UNDETERMINED`. This prevents the "SUITABLE on no evidence" problem.

| Scenario | Verdict | Exit Code |
|----------|---------|-----------|
| All core checks pass, no suspicious findings | SUITABLE | 0 |
| High-confidence suspicious finding | NOT SUITABLE | 1 |
| Medium-confidence suspicious finding | UNDETERMINED | 2 |
| Missing core check | UNDETERMINED | 2 |
| Error condition | UNDETERMINED | 2 |

## Version Information

| Property | Value |
|----------|-------|
| Current Version | 0.1.0 |
| Python Required | 3.10+ |
| Supported Formats | GGUF v2, GGUF v3 |
| Supported Runtimes | llama.cpp |
| Dependencies | Jinja2 (template AST analysis) |
| License | Apache 2.0 |

## Quick Links

- [GitHub Repository](https://github.com/cancerbero-security/cancerbero)
- [Issue Tracker](https://github.com/cancerbero-security/cancerbero/issues)
- [Security Policy](../SECURITY.md)
- [Changelog](../CHANGELOG.md)

## Documentation Structure

```
docs/
├── README.md                    # This file
├── guides/                      # User guides
│   ├── index.md                 # Guide index
│   ├── installation.md          # Installation guide
│   ├── quickstart.md            # Quick start guide
│   ├── configuration.md         # Configuration guide
│   ├── how-it-works.md          # Architecture guide
│   ├── reports.md               # Report interpretation
│   ├── batch.md                 # Batch processing
│   ├── cicd.md                  # CI/CD integration
│   ├── custom-advisories.md     # Custom advisory rules
│   ├── delegates.md             # Third-party tool delegates
│   ├── hardening.md             # Hardening recommendations
│   └── troubleshooting.md       # Troubleshooting guide
├── security/                    # Security documentation
│   ├── index.md                 # Security index
│   ├── threat-model.md          # Threat model
│   ├── poisoned-templates.md    # Poisoned GGUF templates
│   ├── rules-file-backdoor.md   # Rules File Backdoor
│   ├── hf-ui-blindspot.md       # HF UI Blindspot
│   ├── enhanced-template-security.md  # Enhanced template security
│   ├── enhanced-companion-security.md # Enhanced companion security
│   ├── model-card-analysis.md   # Model card analysis
│   ├── quantization-integrity.md # Quantization integrity
│   ├── runtime-config-security.md # Runtime configuration security
│   ├── supply-chain-verification.md # Supply chain verification

│   └── advisories.md            # Advisory database
├── reference/                   # Technical reference
│   ├── index.md                 # Reference index
│   ├── cli.md                   # CLI reference
│   ├── output-formats.md        # Output formats
│   ├── findings.md              # Finding model
│   ├── exit-codes.md            # Exit codes
│   └── config-file.md           # Configuration file
└── examples/                    # Examples
    ├── github-actions.yml       # GitHub Actions example
    └── gitlab-ci.yml            # GitLab CI example
```

## Getting Started

### 1. Install Cancerbero

```bash
# From source
git clone https://github.com/cancerbero-security/cancerbero.git
cd cancerbero
pip install -e .

# Or with uv
uv pip install cancerbero
```

### 2. Check Your First Model

```bash
# For SUITABLE verdict, provide runtime
cancerbero check ./my-model.gguf --runtime ./llama-cli --runtime-version b8146

# Without runtime, verdict will be UNDETERMINED
cancerbero check ./my-model.gguf
```

### 3. Understand the Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Cancerbero — SUITABLE
  No blocking conditions found within the checks performed.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TARGETS
  Artifact : MyModel  (GGUF v3, llama, 100 tensors)
  File     : ./my-model.gguf
  Template : present (5000 chars)
  Bundle   : 2026.08.28  (digest bf844af458f21184…, canonical_sha256_verified)

COVERAGE
  3 clean · 4 unchecked

  This is a suitability assessment, not a safety certification.
  Absence of findings does not prove the artifact is safe.
```

### 4. Learn More

- [Quick Start Guide](guides/quickstart.md) — Detailed first inspection walkthrough
- [Understanding Reports](guides/reports.md) — How to interpret results
- [Security Documentation](security/index.md) — What Cancerbero detects

## Contributing

We welcome contributions! See our [Contributing Guide](../CONTRIBUTING.md) for details.

### Reporting Issues

- [Bug Reports](https://github.com/cancerbero-security/cancerbero/issues/new?template=bug_report.md)
- [Feature Requests](https://github.com/cancerbero-security/cancerbero/issues/new?template=feature_request.md)
- [Security Vulnerabilities](../SECURITY.md)

### Development

```bash
# Clone and install
git clone https://github.com/cancerbero-security/cancerbero.git
cd cancerbero
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check src tests
```

## License

Cancerbero is licensed under the Apache License 2.0. See [LICENSE](../LICENSE) for details.

## Acknowledgments

- [Pillar Security](https://www.pillar.security/) for research on poisoned GGUF templates and Rules File Backdoor
- [llama.cpp](https://github.com/ggml-org/llama.cpp) for the GGUF format and runtime
- [OWASP](https://owasp.org/) for the Top 10 for LLM Applications
- [NIST](https://www.nist.gov/) for the AI Risk Management Framework
