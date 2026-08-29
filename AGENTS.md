# AGENTS.md — How AI agents should use Cancerbero

This document is the canonical guide for any AI agent (Claude Code,
OpenAI Codex CLI, Cursor, or a custom agent built on the Anthropic /
OpenAI / MCP SDK) that wants to inspect GGUF artifacts and llama.cpp
runtimes for safety before they are loaded into an inference pipeline.

Cancerbero is a **read-only, offline-first** tool. It does not execute
the model, does not need network access, and does not require any
GPU or runtime. Its job is to look at the bytes on disk and the
declarations in companion files, and to render a verdict the agent
can trust.

## 1. When to use Cancerbero

Reach for Cancerbero when any of the following is true:

- The agent is about to recommend a specific GGUF artifact to load
  (e.g. "use `Qwen3-30B-A3B-Instruct-Q4_K_M.gguf`").
- The agent is asked to evaluate or compare two or more models
  (which one is "safer", which one is "production-ready").
- The agent is processing a model card, a Hugging Face listing, or
  a download URL and needs to ground its claims in concrete checks.
- The agent is building a CI gate that runs on every model update.
- The agent is reviewing a chat template that is going to be rendered
  by a sandboxed Jinja2 engine.

Do **not** reach for Cancerbero when:

- The user wants the model to *answer a question*; Cancerbero is
  not a chatbot.
- The user is asking about model *capabilities* (MMLU scores,
  reasoning, language coverage). Cancerbero is a security tool, not
  an evaluation harness.
- The model is already loaded in memory; Cancerbero never touches
  weights.

## 2. How to talk to Cancerbero

There are three surfaces, all driven by the same `TOOL_DEFINITIONS`
catalogue in `src/cancerbero/agentic/schemas.py`. The choice depends
on the runtime:

| Surface | Use when | Invocation |
|---|---|---|
| **MCP server** (`cancerbero mcp`) | The agent is Claude Code, OpenAI Codex CLI, Cursor, or any MCP-aware client. | Add the server to the client's MCP configuration; the tools appear as native tool calls. |
| **JSON-schema tools** | The agent is custom and consumes the OpenAI or Anthropic `tools` format. | `cancerbero agentic-manifest` returns the catalogue; the agent calls `safe_invoke_tool` directly. |
| **CLI** | A human runs the tool, or the agent shells out. | `cancerbero check <path> [--runtime <binary>]` |

The MCP and JSON-schema surfaces are **strictly equivalent**: both
expose the same seven tools with the same input/output shapes. The
manifest is the single source of truth.

### 2.1 MCP server

Add Cancerbero to your MCP client configuration. For Claude Code,
the configuration is `~/.config/claude/mcp.json` (Linux) or
`~/Library/Application Support/Claude/mcp.json` (macOS):

```json
{
  "mcpServers": {
    "cancerbero": {
      "command": "cancerbero",
      "args": ["mcp"]
    }
  }
}
```

For OpenAI Codex CLI (`~/.codex/config.toml`):

```toml
[mcp_servers.cancerbero]
command = "cancerbero"
args = ["mcp"]
```

The agent can then call `cancerbero_inspect`, `cancerbero_check_template`,
`cancerbero_companion_scan`, etc. as native tool calls. The full
parameter schema is shown in the tool's `inputSchema` (Anthropic) or
`function.parameters` (OpenAI) field.

### 2.2 JSON-schema tools (non-MCP clients)

Run `cancerbero agentic-manifest` to print the catalogue in
Anthropic's `tools` format. Feed the result to your model's tools
array. When the model emits a tool call, route it through
`cancerbero.agentic.dispatch.safe_invoke_tool(name, arguments)`.

Example (Python):

```python
from cancerbero.agentic.dispatch import safe_invoke_tool

result = safe_invoke_tool(
    "cancerbero_inspect",
    {
        "targets": ["./models/qwen3-30b-q4.gguf"],
        "runtime": "./vendor/llama.cpp/build/bin/llama-cli",
        "runtime_version": "b8146",
    },
)
print(result["verdict"], result["summary"])
```

### 2.3 CLI

For shell-out or interactive use, `cancerbero check` is the canonical
entry point. All the documentation in `docs/guides/quickstart.md` and
`docs/guides/agentic.md` applies.

## 3. The seven tools

| Tool | Purpose | When to call it |
|---|---|---|
| `cancerbero_inspect` | Full check: parse the GGUF, analyse the template, scan companion files, hash if requested, join against the advisory bundle. | The first call when asked "is this model safe to load?" |
| `cancerbero_artifact_facts` | Read-only GGUF metadata and tensor descriptors, no companion or template analysis. | A fast first step when you only need to confirm format, architecture, or tensor count. |
| `cancerbero_check_template` | Run the AST + SSTI analysis on a raw template string. | When the agent already has the template text in context. |
| `cancerbero_companion_scan` | Audit a model repository directory (`config.json`, `Modelfile`, README, ...). | Before pulling weights from a new Hugging Face user. |
| `cancerbero_list_advisories` | List every advisory bundled with the current install. | To know what the current version can detect before drawing a conclusion. |
| `cancerbero_hash` | Compute and optionally verify a SHA-256 digest. | Provenance and integrity checks. |
| `cancerbero_self_test` | Run the bundled detection corpus (poisoned templates, false-positive guards). | To verify the installation is functioning before relying on its verdicts. |

## 4. Interpreting the output

Every tool call returns a JSON object with a stable shape. The most
important fields are:

- `verdict` ∈ `{"suitable", "not_suitable", "undetermined", "clean"}`
- `exit_code` ∈ `{0, 1, 2, 3}` (matches the CLI exit codes)
- `findings` is a list of finding objects, each with:
  - `id`: stable, machine-readable identifier
  - `status` ∈ `{"verified", "clean", "suspicious", "unchecked", "not_applicable", "error"}`
  - `severity` ∈ `{"critical", "high", "medium", "low", "info"}`
  - `confidence` ∈ `{"high", "medium", "low"}`
  - `summary`: human-readable one-liner
  - `action`: what to do next, when applicable

The verdict is the single number an agent should branch on:

| Verdict | Exit code | Meaning | Action |
|---|---|---|---|
| `suitable` | 0 | Every core check (`gguf_structure`, `chat_template_static`, `runtime_advisory_join`) produced positive evidence. **Including the runtime advisory join.** | Load the model. |
| `clean` | 0 | No suspicious findings on the checks we actually performed. Typically this means no `--runtime` was supplied, so the runtime advisory join is out of scope. | The model looks clean on what we ran. Re-run with `--runtime` for a SUITABLE verdict. |
| `not_suitable` | 1 | A confirmed risk. At least one SUSPICIOUS finding passed the severity × classification matrix. | Do not load. Read the `findings` list and act on `action`. |
| `undetermined` | 2 | A check ran and could not complete, or a non-runtime core check was missing. | Read the `findings` list — the explanation is in the `summary`. |

**Important.** Cancerbero never asserts that a model is "safe". A
`clean` or `suitable` verdict says "we ran the checks we could and
found nothing blocking"; it is not a safety certification. The
`not_suitable` verdict, in contrast, is a concrete and actionable
negative claim.

## 5. Recipes

### 5.1 Decide whether to recommend a model

```
Agent: "The user asked for the best 30B model for code. Should I
recommend Qwen3-Coder-30B-A3B-Instruct or DeepSeek-Coder-V2-Lite?"

You:  cancerbero_inspect(targets=[
       "./candidates/qwen3-coder-30b-q4.gguf",
       "./candidates/deepseek-coder-v2-lite-q4.gguf"
     ], runtime="./vendor/llama.cpp/build/bin/llama-cli",
     runtime_version="b8146")

Read the verdict for each artifact. Compare `findings` lists. Cite
the specific finding IDs in the recommendation. If both are
`suitable` and one has zero findings, prefer that one.
```

### 5.2 Vet a chat template before adding it to a library

```
Agent: "I drafted this Jinja2 template for a new model. Is it safe?"

You:  cancerbero_check_template(template=template_text)

If any `dangerous_function` or `prompt_injection` finding fires,
reject the template and tell the user which pattern matched.
```

### 5.3 Audit a Hugging Face repository before pulling weights

```
Agent: "Should I clone https://huggingface.co/SomeUser/some-uncertified-model?"

You:  cancerbero_companion_scan(directory="./clones/some-uncertified-model")

If any `cbr.config.companion_security_*` finding fires (hardcoded
credentials, Modelfile FROM URL, Rules File Backdoor, ...), refuse
to proceed. If the directory contains a `config.json` with
`trust_remote_code: true`, that finding alone is enough to block.
```

### 5.4 Verify a downloaded file matches its declared hash

```
Agent: "The provider claims the SHA-256 of model.gguf is
        d4e5f6... (64 hex)."

You:  cancerbero_hash(path="./downloads/model.gguf",
                     expected="d4e5f6...")

If `match` is false, the download is corrupt or tampered with.
Do not load. Re-download or refuse.
```

### 5.5 Plan an upgrade

```
Agent: "llama.cpp just shipped b8500. Should we upgrade from b8146?"

You:  cancerbero_list_advisories()

Read the entries whose `affected` range covers b8146. If any are
`fixed` by b8500, that is the upgrade reason. If b8500 introduces
new advisories not yet patched, hold the upgrade.
```

## 6. What the agent should NOT do

- Do not run Cancerbero on a model that is currently loaded by
  another process. Cancerbero reads the file but does not lock it;
  a concurrent write could produce spurious findings.
- Do not modify the GGUF, the chat template, or any companion file
  and then re-run Cancerbero expecting "clean". Cancerbero's output
  reflects the file you gave it; tampering with the artifact is
  not a workflow it supports.
- Do not interpret a `clean` verdict as a safety seal. It is a
  bounded negative claim. Phrase it as "no suspicious findings
  on the checks performed".
- Do not load a model whose verdict is `not_suitable`. Even
  if the user pushes back. The verdict is the artifact's claim,
  not yours.
- Do not skip the `runtime` parameter if you have one. Without
  it, the runtime advisory join does not run, and the verdict
  cannot reach `suitable`.

## 7. Failure modes and how to recover

- **The tool returned `{"error": "io_error"}`.** The path does not
  exist, is not readable, or is the wrong kind (e.g. directory
  passed to `cancerbero_artifact_facts`). Re-check the path.
- **The tool returned `{"error": "invalid_arguments"}`.** The JSON
  payload did not match the schema. Re-read the tool's
  `inputSchema` and correct the call.
- **The tool returned `{"error": "internal_error"}`.** Cancerbero
  crashed on a real bug. Capture the `message` field and report
  it at https://github.com/noguerol/cancerbero/issues.
- **The verdict is `undetermined` because `runtime_advisory_join`
  is missing.** The artifact was not run against a runtime
  build. Re-run `cancerbero_inspect` with a `runtime` argument.
- **The verdict is `undetermined` because a non-runtime core check
  is missing.** Inspect the `findings` list: a `gguf_structure`
  error means the file is malformed; a `chat_template_static`
  error means the template did not parse. Either way, do not
  load the model.

## 8. Self-test before relying on the verdicts

Before drawing any safety conclusion in a production workflow, run
`cancerbero_self_test`. The function returns a count of true
positives, true negatives, false positives, and false negatives
on a fixed corpus of known-safe and known-bad fixtures. A run that
shows `false_positives > 0` or `false_negatives > 0` indicates the
installation is broken or has been monkey-patched; do not trust
its verdicts until you understand why.

## 9. Versioning and stability

The shape of every tool's output is part of Cancerbero's public
contract. We do not break it without bumping the minor version
and updating `CHANGELOG.md`. The finding `id` strings are also
stable — agents can write rules like "if any finding has id
starting with `cbr.template.security.dangerous_function`, refuse
the model".

## 10. Security model

The MCP server speaks stdio; it does not open any TCP port by
default. The CLI subprocess is the boundary. Cancerbero itself:

- Never executes the model.
- Never opens network sockets (the advisory bundle is embedded).
- Never writes to any path outside the user's request (no
  telemetry, no log files, no temp files in system directories
  beyond `tempfile.NamedTemporaryFile`).
- The embedded bundle is signed and verified on load; updates
  are not auto-fetched.

The agent is responsible for the rest: it must not pass user
input blindly into a tool call (especially `targets` and
`runtime`), and it must surface the verdict to the user instead
of swallowing it.
