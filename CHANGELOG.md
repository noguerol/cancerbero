# Changelog

All notable changes to Cancerbero are documented here.

## 0.2.0 — 2026-08-29

### Added — agentic surface

- **`cancerbero mcp` Model Context Protocol server.** Speaks MCP over
  stdio (no TCP port by default). Exposes seven tools to Claude Code,
  OpenAI Codex CLI, Cursor, and any MCP-aware client:
  `cancerbero_inspect`, `cancerbero_artifact_facts`,
  `cancerbero_check_template`, `cancerbero_companion_scan`,
  `cancerbero_list_advisories`, `cancerbero_hash`,
  `cancerbero_self_test`. The catalogue is the single source of
  truth in `cancerbero.agentic.schemas.TOOL_DEFINITIONS`.
- **`cancerbero agentic-manifest` subcommand.** Prints the tool
  catalogue in Anthropic `tools` format for non-MCP clients.
- **JSON-schema tool catalogue** in
  `cancerbero.agentic.schemas`. Renders as OpenAI
  (`tool_definitions_as_openai_tools`) or Anthropic
  (`tool_definitions_as_anthropic_tools`) `tools` arrays.
- **Python dispatch** in `cancerbero.agentic.dispatch`. `safe_invoke_tool(name, args)`
  routes every agent tool call to the right Cancerbero subsystem
  and converts every exception into a structured `{"error": ...}`
  response so the agent can branch on it.
- **`AGENTS.md`** at the repository root. The canonical contract for
  AI agents: when to use Cancerbero, how to wire it, the seven
  tools, the verdict policy, the failure modes, and the security
  model. Read by Claude Code, OpenAI Codex CLI, Cursor, and 30+
  other agentic clients.
- **Examples directory.** `agent-claude-code.json`,
  `agent-cursor.json`, `agent-codex.toml`,
  `agent-openai-function-calling.py`,
  `agent-anthropic-function-calling.py`, `agent-mcp-client.py` —
  copy-paste-ready wiring for every supported agent runtime.
- **34 new tests** in `tests/unit/test_agentic.py` and
  `tests/integration/test_mcp_server.py` covering the catalogue,
  the dispatcher, the manifest renderer, the CLI helpers, and a
  real end-to-end MCP stdio round-trip.

### Changed

- **Exit code table** now distinguishes `suitable` (exit 0) from
  `clean` (also exit 0) so CI scripts and agents can branch on the
  verdict explicitly.
- **README, docs index, agentic-tools reference, AGENTS.md** all
  describe the new agentic surface and point at the same example
  recipes.
- **Keywords** in `pyproject.toml` extended with `agentic`, `mcp`,
  `llm-security`, `model-context-protocol`.
- **New optional dependency** `[mcp]` (the official Model Context
  Protocol SDK). `[dev]` now also pulls `pytest-asyncio` and `mcp`
  for the integration tests.
- Bundle updated to `2026.08.28.3`; `advisory_count` is now 9.

## 0.1.3 — 2026-08-29

### Fixed

- **False positive on BPE `merges.txt` files.** The Rules File Backdoor
  detector's `<!--...override...-->` regex used `re.DOTALL`, so it
  matched across multiple lines. A real BPE vocabulary that happens
  to contain a token starting with `<!--`, the literal word
  `override` (which is in every English BPE vocabulary), and a token
  containing `-->` would fire as a "hidden instructions" finding. The
  pattern is now single-line only (no `re.DOTALL`) and bounded to 400
  chars before/after the trigger word. 3 regression tests added.
- **Findings invariant relaxed for `not_used` evidence.** When a
  companion-file signal is `runtime_relevance="not_used"` (e.g.
  Ollama-only `Modelfile` checked under `llama.cpp`), the
  ConfigInspection normalizer now downgrades the severity to INFO so
  the `status != SUSPICIOUS ⇒ severity ∈ {INFO, LOW}` invariant holds.
  Raw severity is preserved in `evidence["raw_severity"]`.

## 0.1.2 — 2026-08-29

### Fixed

- **False positive on benign Jinja2 globals.** The 0.1.1 SSTI fix flagged
  every call to `namespace(...)`, `cycler(...)`, `lipsum(...)`,
  `joiner(...)` as suspicious because their `__init__.__globals__` is a
  known SSTI gateway. These globals are standard Jinja2 idioms used by
  every modern chat template (Qwen3 tool-call state tracking,
  llama.cpp's own templates, Gemma, DeepSeek); plain invocation is
  benign. Detection now requires a dunder attribute somewhere in the
  call chain, matching only the actual SSTI gadgets
  (`namespace.__init__.__globals__.os.popen(...)` etc.). 5 regression
  tests added covering the false-positive patterns and 1 covering the
  legitimate SSTI path that must still fire.

## 0.1.1 — 2026-08-29

### Security hardening (external audit remediation)

#### Critical

- **GGUF parser no longer aborts on real BPE tokenizers** (`C1`). The retained metadata budget is now 64 MiB (was 8 MiB), with a dedicated 16 MiB reservation for essential keys (`tokenizer.chat_template`, `general.architecture`, `general.name`, `general.alignment`, `general.file_type`, `general.quantization_version`). The parser silently omits non-essential keys instead of crashing; a new `cbr.gguf.metadata_omitted` finding surfaces the coverage gap. Llama 3, Qwen 2.5, Mistral-Nemo, and DeepSeek models now parse correctly.
- **Poisoned-template detection covers arbitrary-depth SSTI chains** (`C2`). `cbr.template.security.dangerous_function` now triggers for `''.__class__.__mro__[1].__subclasses__()`, `self.__init__.__globals__.__builtins__.__import__('os')`, `cycler.__init__.__globals__.os.popen(...)`, `lipsum.__globals__[...]`, and `|attr('__class__')`. URL exfiltration via `Add`/`Concat` (`{{ 'https://x/' + msg }}`, `{{ 'https://x/' ~ msg }}`) is now detected. A new `cbr.template.prompt_injection` finding catches instruction strings concatenated to user input.
- **Every GGUF artifact in a directory is now inspected** (`C3`). The dead `if target not in targets else None` conditional was removed. Template analysis, companion-file inspection, hashing, and the advisory join now iterate over every artifact, so a poisoned template in the second GGUF of a directory no longer hides behind the first one.

#### High

- **Companion-file severity is propagated to the verdict** (`G1`). `ConfigInspection.findings` now honours the per-evidence `severity` field; high-severity signals (hardcoded credentials, `trust_remote_code`, `auto_map`, `remote FROM URL`, Discord/Slack webhooks) become `SUSPICIOUS` findings that block the verdict. The enhanced patterns now apply to `*.json`, `Modelfile`, `.cursorrules`, and `.github/copilot-instructions.md`.
- **Dead quantization-integrity checks removed** (`G2`). The reader already rejects unknown tensor types, misaligned offsets, and zero-sized dimensions; the parallel inspector checks could only be exercised against in-memory `GgufDocument` instances. See `docs/decisions/0003-quantization-integrity-scope.md`.
- **`CLEAN` verdict differentiates "ran the checks we could" from "everything passed"** (`G3`). Without `--runtime`, Cancerbero now exits 0 with verdict `CLEAN` and emits a `cbr.join.no_runtime` UNCHECKED finding; the runtime advisory join is no longer a hard core-check requirement when no runtime is in scope.

#### Medium

- **Advisory bundle covers CVE-2026-43631** (`M1`). Added `GHSA-6hc7-9rph-cm99` (use-after-free in `llama-server` with `--sleep-idle-seconds`, builds b7492–b9060). Bundle version bumped to `2026.08.28.2`.
- **Template-poison finding IDs are unique per occurrence** (`M2`). Multiple `os.system` calls now produce `cbr.template.security.dangerous_function.0`, `.1`, … — `--explain` and deduplication work.
- **Templates are parsed exactly once** (`M3`). `_analyze_template` reuses the AST across the structural and poison-risk passes.
- **SARIF results carry physical locations and valid fixes** (`M4`). Every result has a `locations[0].physicalLocation.artifactLocation.uri`; every fix has at least one `artifactChanges` entry.
- **`--no-color`/`--no-banner`/`--no-interactive` work in any position** (`M5`). The flags live on a shared parent parser and are attached to every subcommand; the ASCII banner is suppressed on non-TTY stderr.
- **Hash runs before companion-file inspection** (`M6`). Manifest SHA-256 coherence checks now receive the freshly computed digest.
- **`Finding.classification` defaults to `confidence`** (`M7`). Findings without an explicit `classification` no longer silently default to HIGH and accidentally block the verdict.
- **Provenance URLs point at the published repository** (`blue`). `pyproject.toml`, SARIF output, hardening recommendations, and `docs/` all reference `github.com/noguerol/cancerbero`.
- **`cancerbero_version` is read from the package metadata** (`blue`). `run_check` no longer hardcodes `0.1.0` in the audit report.
- **`general.source.url` is no longer flagged** (`blue`). The metadata-safety check now allowlists a small set of benign provenance keys so every modern model doesn't trip a `URL in metadata` finding.
- **`hidden_instruction` requires an override keyword AND a strong signal** (`blue`). Legitimate prose mentioning "ignore" no longer trips the check.
- **`GGML_TYPE_SIZES` documents its experimental entries** (`blue`). Entries 100–108 are tagged as ROCm fork-specific.

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
- **Quantization Integrity**: Tensor invariants are enforced by the parser itself (type ids, alignment, dimension size); the inspector no longer carries a parallel set of checks that could never fire against a parsed file. See `docs/decisions/` for the rationale.
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
