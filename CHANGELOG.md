# Changelog

All notable changes to Cancerbero are documented here.

## 0.1.0 — 2026-08-28

### Core Features
- Defensive GGUF v2/v3 metadata-only parser with fuzzing
- Static llama.cpp build/runtime identification
- Artifact × runtime × advisory join engine
- Static chat-template AST analysis with poison detection
- Companion file inspection with Rules File Backdoor detection
- Optional SHA-256 hash verification
- Terminal, JSON, Markdown, and SARIF report output
- Configuration file support (`cancerbero.yaml`)
- Interactive and non-interactive modes

### Verdict Policy
- Severity × classification matrix for verdict determination
- Core checks: `gguf_structure`, `chat_template_static`, `runtime_advisory_join`
- Missing core check → UNDETERMINED
- High-confidence suspicious → NOT SUITABLE
- Medium-confidence suspicious → UNDETERMINED

### Security Analysis
- **Template Security**: Poisoned GGUF templates, dangerous functions, exfiltration patterns, encoded payloads
- **Companion File Security**: Hardcoded credentials, remote code execution, network exfiltration
- **Model Card Analysis**: Credential harvesting, shortened URLs
- **Quantization Integrity**: Tensor misalignment detection
- **Runtime Configuration**: Network exposure, API key in arguments
- **Supply Chain Verification**: Impossible quantization, suspicious file types
- **Configuration Hardening**: Actionable security recommendations

### Advisory Database
- 7 advisory rules covering CVE-2024-32878, CVE-2024-34359, CVE-2026-27940, CVE-2026-33298, CVE-2026-5760, CVE-2026-7482, GGUF-2026-05-001
- Verified sources with audit trail

### Third-Party Tool Delegates
- ModelAudit integration (42+ format scanning)

- PickleScan integration (pickle bytecode analysis)
- Fickling integration (allowlist-based pickle scanning)
- ModelScan integration (multi-framework model scanning)

### Tests
- 287 tests covering all functionality
- Unit tests, integration tests, performance tests
- Zero telemetry verification
- Resource limits testing

### Documentation
- Comprehensive security documentation (9 guides)
- User guides (8 guides)
- Technical reference (6 documents)
- CI/CD examples (GitHub Actions, GitLab CI)
- Decision records (ADR 0001, ADR 0002)
