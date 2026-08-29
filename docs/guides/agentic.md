# Cancerbero for AI agents

Cancerbero is built to be driven by AI agents. Every check the CLI
performs is also exposed as a structured tool call, and the same
seven tools are reachable from three surfaces — pick whichever
fits your agent runtime.

> See the canonical agent contract in
> [`AGENTS.md`](../../AGENTS.md). This guide is the
> reference manual for the surfaces, with examples.

## The three surfaces

| Surface | Best for | How the agent invokes it |
|---|---|---|
| **MCP server** (`cancerbero mcp`) | Claude Code, OpenAI Codex CLI, Cursor, or any MCP-aware client | Add `cancerbero mcp` to the client's MCP config; the tools appear as native tool calls. |
| **JSON-schema tools** | Custom agents that consume the OpenAI or Anthropic `tools` format | `cancerbero agentic-manifest` emits the catalogue; the agent calls `safe_invoke_tool(name, arguments)` directly. |
| **CLI** | Humans or agents that shell out | `cancerbero check <path> [--runtime <binary>]` — see [`quickstart.md`](./quickstart.md). |

The MCP and JSON-schema surfaces are **strictly equivalent**: both
expose the same seven tools with the same parameter shapes and the
same JSON output. The catalogue is the single source of truth
(`src/cancerbero/agentic/schemas.py`).

## The seven tools

| Tool | Purpose | Use when |
|---|---|---|
| `cancerbero_inspect` | Full check: GGUF parse, template analysis, companion scan, advisory join, optional hash | The user asks "is this model safe to load?" |
| `cancerbero_artifact_facts` | Read-only GGUF metadata and tensor descriptors, no companion or template analysis | You need a fast fact lookup (architecture, tensor count, template presence). |
| `cancerbero_check_template` | AST + SSTI analysis on a raw template string | The agent already has the template text in context. |
| `cancerbero_companion_scan` | Audit a directory of companion files (`config.json`, `Modelfile`, README, etc.) | Before pulling weights from an unknown Hugging Face user. |
| `cancerbero_list_advisories` | List every advisory bundled with the current install | You want to know what the current build can detect before drawing conclusions. |
| `cancerbero_hash` | Stream a file through SHA-256, optionally compare to an expected digest | Provenance and integrity checks. |
| `cancerbero_self_test` | Run the bundled poisoned-template corpus | Before relying on verdicts in a production workflow. |

## Surface 1 — MCP server

The MCP server speaks the [Model Context Protocol](https://modelcontextprotocol.io)
over stdio (no TCP port by default). Every tool is exposed with a
typed `inputSchema` derived from the JSON Schema in
`agentic/schemas.py`.

### Claude Code

Add to `~/.config/claude/mcp.json` (Linux) or
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

Restart Claude Code. The tools appear in the available tool list
prefixed with `mcp__cancerbero__`. The agent can then call e.g.
`mcp__cancerbero__cancerbero_inspect` directly.

### OpenAI Codex CLI

Add to `~/.codex/config.toml`:

```toml
[mcp_servers.cancerbero]
command = "cancerbero"
args = ["mcp"]
```

### Cursor

Add to `~/.cursor/mcp.json` (project or user):

```json
{
  "mcpServers": {
    "cancerbero": { "command": "cancerbero", "args": ["mcp"] }
  }
}
```

### Verifying the server is reachable

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.0.1"}}}' \
  | cancerbero mcp
```

You should see an `initialize` response with the server's
`serverInfo` and the tool catalogue. The server is then ready to
accept `tools/call` requests.

## Surface 2 — JSON-schema tools

For agents that consume the OpenAI or Anthropic `tools` format
without MCP, run:

```bash
cancerbero agentic-manifest
```

The output is the catalogue in Anthropic format. Feed it to your
model in the `tools` array. When the model emits a tool call,
route it through `cancerbero.agentic.dispatch.safe_invoke_tool`:

```python
from cancerbero.agentic.dispatch import safe_invoke_tool
import json

result = safe_invoke_tool(
    "cancerbero_inspect",
    {
        "targets": ["./models/qwen3-30b-q4.gguf"],
        "runtime": "./vendor/llama.cpp/build/bin/llama-cli",
        "runtime_version": "b8146",
    },
)
if result["verdict"] == "not_suitable":
    for finding in result["findings"]:
        if finding["status"] == "suspicious":
            print(finding["id"], finding["summary"])
```

### Output format

Every tool returns a JSON object with the same top-level fields:

```json
{
  "verdict": "not_suitable" | "suitable" | "undetermined" | "clean",
  "exit_code": 0 | 1 | 2,
  "summary": "Verdict: not_suitable. 1 suspicious finding(s). First: cbr.template.security.dangerous_function.0 — Template calls dangerous function 'os.system'.",
  "artifacts": [...],
  "runtimes": [...],
  "findings": [
    {
      "id": "cbr.template.security.dangerous_function.0",
      "head": "loading",
      "check": "template_poison_detection",
      "status": "suspicious",
      "severity": "high",
      "confidence": "high",
      "classification": "high",
      "summary": "Template calls dangerous function 'os.system'.",
      "action": "Do not load this model. ...",
      "evidence": {"line": 1},
      "references": ["https://www.pillar.security/..."],
      "mandatory": true
    }
  ],
  "bundle": { "version": "2026.08.28.3" }
}
```

Stable values:
- `verdict ∈ {"suitable", "not_suitable", "undetermined", "clean"}`
- `exit_code ∈ {0, 1, 2, 3}` (matches the CLI)
- `findings[].id` strings are stable across releases (see CHANGELOG)

## Surface 3 — CLI

The CLI is fully documented in [`quickstart.md`](./quickstart.md) and
[`cli.md`](../reference/cli.md). The relevant agent-facing flags
are:

- `--runtime PATH` — path to a llama.cpp binary; required for
  SUITABLE.
- `--runtime-version b8146` — override when the binary is not
  writable (e.g. a CI sandbox).
- `--full` — stream a complete SHA-256 (slow on large models).
- `--expected-sha256 HEX` — verify against a known digest.
- `--format json` — machine-readable output, suitable for piping.

## Recipes

### Decide which of two models to recommend

```python
from cancerbero.agentic.dispatch import safe_invoke_tool

for path in ["./qwen3-30b-q4.gguf", "./deepseek-coder-v2-lite-q4.gguf"]:
    result = safe_invoke_tool(
        "cancerbero_inspect",
        {"targets": [path], "runtime": "./llama-cli", "runtime_version": "b8146"},
    )
    suspicious = sum(1 for f in result["findings"] if f["status"] == "suspicious")
    print(f"{path}: {result['verdict']} ({suspicious} suspicious)")
```

### Vet a chat template before adding it to a library

```python
result = safe_invoke_tool(
    "cancerbero_check_template",
    {"template": open("templates/my-template.jinja").read()},
)
if result["verdict"] == "not_suitable":
    raise ValueError(f"Template is unsafe: {result['summary']}")
```

### Audit a Hugging Face repository before pulling weights

```python
result = safe_invoke_tool(
    "cancerbero_companion_scan",
    {"directory": "./clones/SomeUser/uncertified-model"},
)
if any(
    f["id"].startswith("cbr.config.companion_security_")
    and f["status"] == "suspicious"
    for f in result["findings"]
):
    print("Refusing to pull: companion-file risk detected.")
```

## Self-test before relying on the verdicts

Before drawing any safety conclusion in a production workflow, run
`cancerbero_self_test`. The function returns a count of true
positives, true negatives, false positives, and false negatives
on a fixed corpus of known-safe and known-bad fixtures. A run that
shows `false_positives > 0` or `false_negatives > 0` indicates the
installation is broken or has been monkey-patched; do not trust
its verdicts until you understand why.

## Versioning

The shape of every tool's output is part of Cancerbero's public
contract. We do not break it without bumping the minor version
and updating `CHANGELOG.md`.

The finding `id` strings are also stable — agents can write rules
like "if any finding has id starting with
`cbr.template.security.dangerous_function`, refuse the model".
