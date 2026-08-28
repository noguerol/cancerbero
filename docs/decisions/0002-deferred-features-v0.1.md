# ADR 0002: Deferred Features for v0.1

## Status

Accepted

## Date

2026-08-28

## Context

During the implementation of Cancerbero v0.1, several features were identified as out of scope for the initial release. This decision record documents what was deferred and why.

## Decisions

### 1. Bundle Signing (Deferred)

**Decision**: Defer bundle signing and signature verification to a future release.

**Rationale**:
- The embedded bundle inherits the distribution's authenticity (wheel signing, PyPI verification)
- Implementing custom cryptography (TUF, Sigstore) adds complexity without proportional value in v0.1
- The bundle's integrity is verified via SHA-256 digest, which is sufficient for local use

**Consequences**:
- Tasks 18, 64-65 are deferred
- Bundle integrity relies on distribution-level trust
- Future versions may add optional OMS/Sigstore verification

### 2. ModelAudit Integration (Deferred)

**Decision**: Defer ModelAudit integration to a future release.

**Rationale**:
- ModelAudit is an external tool with its own dependencies and telemetry
- Cancerbero's core value proposition is the artifact × runtime × advisory join, not reimplementing existing tools
- Integrating ModelAudit requires careful telemetry handling and subprocess management

**Consequences**:
- Tasks 37-41, 71 are deferred
- Cancerbero focuses on what it can verify statically (templates, metadata, advisories)
- Future versions may add optional ModelAudit integration with explicit telemetry controls

### 3. Audit History Storage (Deferred)

**Decision**: Defer audit history storage to a future release.

**Rationale**:
- Local audit storage (`~/.cancerbero/audits/`) adds state management complexity
- Users can already save reports via `--json` flag
- Audit history is a convenience feature, not a security requirement

**Consequences**:
- Task 49 is deferred
- Users manage their own report storage
- Future versions may add optional audit history

### 4. Template Render Sandbox (Deferred)

**Decision**: Defer template render testing to a future release.

**Rationale**:
- Rendering untrusted templates is inherently risky, even in a sandbox
- Static analysis (AST inspection) catches the most critical patterns without execution risk
- A proper sandbox requires significant implementation effort (subprocess, resource limits, etc.)

**Consequences**:
- Task 34 is deferred
- Template analysis remains purely static (AST-based)
- Future versions may add optional render testing in a disposable subprocess

### 5. Zero Telemetry Verification (Implemented)

**Decision**: Implement comprehensive zero-telemetry verification tests.

**Rationale**:
- Cancerbero's "no telemetry" claim must be verifiable
- Static analysis of imports and dependencies provides strong guarantees
- Tests serve as documentation of the no-telemetry commitment

**Implementation**:
- `tests/unit/test_zero_telemetry.py` verifies:
  - No `requests`, `httpx`, `urllib3`, `aiohttp` imports
  - No `urllib.request` or `socket` imports
  - No analytics/tracking strings
  - Minimal runtime dependencies (only Jinja2)
  - No telemetry environment variables

## Consequences

### For v0.1

- Cancerbero v0.1 focuses on what can be verified statically:
  - GGUF structural validation
  - Template AST analysis
  - Companion file inspection
  - Advisory join (artifact × runtime × advisory)
  - SHA-256 hash verification
- External tool integrations are deferred
- Cryptographic signing is deferred

### For Future Versions

- Bundle signing may be added as an optional feature
- ModelAudit integration may be added with explicit telemetry controls
- Template render testing may be added in a sandboxed subprocess
- Audit history may be added as a convenience feature

## References

- [AGENTS.md](../../AGENTS.md) — Project guidelines
- [PRD](../../deep-research-llm-security/10-cancerbero-producto.md) — Product requirements
- [SECURITY.md](../../SECURITY.md) — Security policy
