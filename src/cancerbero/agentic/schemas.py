"""Stable, machine-readable tool definitions for Cancerbero.

The schemas in this module describe every agent-callable capability
exposed by Cancerbero in three forms:

* As JSON Schema objects (compatible with the OpenAI ``tools`` array
  and the Anthropic ``tools`` API);
* As Python data classes that can be dumped to JSON for inspection;
* As the single source of truth for the MCP server in
  ``cancerbero.mcp_server`` — both surfaces must stay in lockstep.

Keeping the definitions here means a tooling change in one place
propagates to every agent runtime, and the documented surface cannot
drift from the implementation.

A new agent integration typically:

1. Reads ``TOOL_DEFINITIONS`` (a list of ``ToolDefinition``);
2. Passes them to the model in the format expected by the provider;
3. For each tool call the model emits, calls
   ``invoke_tool(name, arguments)`` and feeds the JSON result back
   into the conversation.

For MCP-aware clients (Claude Code, Cursor, OpenAI Codex CLI, etc.),
prefer the MCP server (``cancerbero mcp``) over the JSON schema path;
both surface the same capabilities.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Verdict enums (stable, included in the JSON output for every tool call).
# Agents can rely on these literal values.
# ---------------------------------------------------------------------------

VERDICT_VALUES = ("suitable", "not_suitable", "undetermined", "clean")
STATUS_VALUES = (
    "verified",
    "clean",
    "suspicious",
    "unchecked",
    "not_applicable",
    "error",
)
SEVERITY_VALUES = ("critical", "high", "medium", "low", "info")
CONFIDENCE_VALUES = ("high", "medium", "low")


# ---------------------------------------------------------------------------
# ToolDefinition.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """One agent-callable capability.

    The ``parameters`` field is a JSON Schema object describing the
    input. ``output_schema`` is a small JSON Schema sketch of the
    returned object so an agent can introspect the shape without
    firing the tool.
    """

    name: str
    description: str
    parameters: dict[str, Any]
    output_schema: dict[str, Any] = field(default_factory=dict)

    def to_openai_tool(self) -> dict[str, Any]:
        """Render as an OpenAI/Anthropic ``tools`` entry."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


# ---------------------------------------------------------------------------
# Parameter schema fragments (kept tiny and re-used).
# ---------------------------------------------------------------------------

_TARGET_PATH_SCHEMA: dict[str, Any] = {
    "type": "string",
    "description": (
        "Absolute or relative path to a local GGUF file, a directory"
        " containing GGUF files, or a llama.cpp runtime binary."
        " The tool detects the target type from the path or contents."
    ),
}

_RUNTIME_OVERRIDE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": (
        "Optional override for the runtime identification."
        " If omitted, Cancerbero tries to identify the runtime from"
        " the path or its environment."
    ),
    "properties": {
        "path": _TARGET_PATH_SCHEMA,
        "version": {
            "type": "string",
            "description": (
                "Trusted runtime semver or ``bNNNN`` build number."
                " Use this when the runtime is not discoverable from"
                " the binary itself (for example in a CI sandbox)."
            ),
        },
    },
    "additionalProperties": False,
}

_VERDICT_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["verdict", "exit_code"],
    "properties": {
        "verdict": {
            "type": "string",
            "enum": list(VERDICT_VALUES),
            "description": (
                "Overall suitability. ``suitable`` and ``clean`` exit 0,"
                " ``not_suitable`` exits 1, ``undetermined`` exits 2."
            ),
        },
        "exit_code": {"type": "integer", "minimum": 0, "maximum": 3},
        "summary": {
            "type": "string",
            "description": "One-paragraph human-readable summary.",
        },
    },
}


# ---------------------------------------------------------------------------
# The tool catalogue.
# ---------------------------------------------------------------------------


TOOL_DEFINITIONS: tuple[ToolDefinition, ...] = (
    ToolDefinition(
        name="cancerbero_inspect",
        description=(
            "Run the full Cancerbero check on one or more targets. Returns"
            " the verdict, the list of findings, optional SHA-256 digests,"
            " and the per-artifact / per-runtime facts. This is the default"
            " tool to call when an agent needs to decide whether a GGUF"
            " artifact and an optional llama.cpp runtime are safe to load."
        ),
        parameters={
            "type": "object",
            "required": ["targets"],
            "properties": {
                "targets": {
                    "type": "array",
                    "items": _TARGET_PATH_SCHEMA,
                    "minItems": 1,
                    "description": (
                        "One or more paths to inspect. A path may be a"
                        " single ``.gguf`` file, a directory of GGUFs, or"
                        " a llama.cpp binary. Directory targets are"
                        " expanded to all GGUF files inside."
                    ),
                },
                "runtime": {
                    "type": "string",
                    "description": (
                        "Path to a llama.cpp runtime binary. When set,"
                        " Cancerbero joins the advisory bundle against the"
                        " detected runtime build. Optional but recommended."
                    ),
                },
                "runtime_version": {
                    "type": "string",
                    "description": (
                        "Override the runtime version, e.g. ``b8146`` or"
                        " ``0.2.72``. Useful in CI when the runtime build"
                        " is known but the binary is not writable."
                    ),
                },
                "full_hash": {
                    "type": "boolean",
                    "default": False,
                    "description": (
                        "Stream each artifact to compute a complete"
                        " SHA-256. Slower but enables provenance checks."
                    ),
                },
                "expected_sha256": {
                    "type": "string",
                    "pattern": "^[0-9a-fA-F]{64}$",
                    "description": (
                        "Expected digest of the FIRST target. Forces"
                        " ``full_hash`` and surfaces a SUSPICIOUS finding"
                        " on mismatch."
                    ),
                },
            },
            "additionalProperties": False,
        },
        output_schema=_VERDICT_RESPONSE_SCHEMA,
    ),
    ToolDefinition(
        name="cancerbero_artifact_facts",
        description=(
            "Read the GGUF metadata and tensor descriptors of a single"
            " artifact WITHOUT running template or companion analysis."
            " Useful as a fast first step before deciding whether the"
            " full check is warranted. Returns the same ``ArtifactFacts``"
            " payload as ``cancerbero_inspect`` but with no findings."
        ),
        parameters={
            "type": "object",
            "required": ["path"],
            "properties": {"path": _TARGET_PATH_SCHEMA},
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {
                "facts": {
                    "type": "object",
                    "description": (
                        "GGUF metadata (architecture, file type, alignment,"
                        " tensor count, chat_template, sha256, ...)."
                    ),
                }
            },
        },
    ),
    ToolDefinition(
        name="cancerbero_check_template",
        description=(
            "Run the chat-template analysis on a single template string"
            " without needing a GGUF file. Reports AST findings, SSTI"
            " gadgets, exfiltration URLs, and prompt-injection patterns."
            " Use this when the agent already has the template text in"
            " context and wants to know whether it is safe to render."
        ),
        parameters={
            "type": "object",
            "required": ["template"],
            "properties": {
                "template": {
                    "type": "string",
                    "description": "Raw Jinja2 template text to inspect.",
                },
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": (
                        "List of findings with id, head, check, status,"
                        " severity, confidence, summary, evidence."
                    ),
                },
                "verdict": {
                    "type": "string",
                    "enum": list(VERDICT_VALUES),
                },
            },
        },
    ),
    ToolDefinition(
        name="cancerbero_companion_scan",
        description=(
            "Run the companion-file security scan on a directory without"
            " inspecting a GGUF file. Detects hardcoded credentials,"
            " Modelfile FROM URLs, Rules File Backdoor patterns, and"
            " metadata mismatches. Use this when the agent needs to"
            " audit a model repository before pulling weights."
        ),
        parameters={
            "type": "object",
            "required": ["directory"],
            "properties": {
                "directory": {
                    "type": "string",
                    "description": "Path to a directory of companion files.",
                },
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {
                "findings": {"type": "array", "items": {"type": "object"}},
                "files_inspected": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
        },
    ),
    ToolDefinition(
        name="cancerbero_list_advisories",
        description=(
            "Return the list of advisories bundled with this Cancerbero"
            " installation. Each entry includes the affected component,"
            " build / version range, severity, and source URL. Use this"
            " to understand what the current build can detect before"
            " drawing a conclusion from a verdict."
        ),
        parameters={"type": "object", "properties": {}, "additionalProperties": False},
        output_schema={
            "type": "object",
            "properties": {
                "advisories": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "title": {"type": "string"},
                            "component": {"type": "string"},
                            "severity": {"type": "string"},
                            "affected": {"type": "object"},
                            "fixed": {"type": "object"},
                        },
                    },
                },
                "bundle_version": {"type": "string"},
            },
        },
    ),
    ToolDefinition(
        name="cancerbero_hash",
        description=(
            "Compute the SHA-256 of a file and optionally compare it"
            " against an expected digest. Fast (no template or companion"
            " analysis). Use this to confirm the integrity of a model"
            " weight before running the full check."
        ),
        parameters={
            "type": "object",
            "required": ["path"],
            "properties": {
                "path": _TARGET_PATH_SCHEMA,
                "expected": {
                    "type": "string",
                    "pattern": "^[0-9a-fA-F]{64}$",
                    "description": "Optional expected SHA-256 to compare against.",
                },
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {
                "sha256": {"type": "string"},
                "match": {
                    "type": "boolean",
                    "description": (
                        "True if the expected digest matches. ``null`` if"
                        " no expected digest was supplied."
                    ),
                },
            },
        },
    ),
    ToolDefinition(
        name="cancerbero_self_test",
        description=(
            "Run a self-test against a list of known-safe and known-bad"
            " fixtures bundled with Cancerbero. Returns the count of"
            " true positives, true negatives, false positives, and false"
            " negatives. Use this to verify that the current installation"
            " is functioning before relying on its verdicts."
        ),
        parameters={"type": "object", "properties": {}, "additionalProperties": False},
        output_schema={
            "type": "object",
            "properties": {
                "true_positives": {"type": "integer"},
                "true_negatives": {"type": "integer"},
                "false_positives": {"type": "integer"},
                "false_negatives": {"type": "integer"},
            },
        },
    ),
)


def tool_definitions_as_openai_tools() -> list[dict[str, Any]]:
    """Return the tool catalogue as a list of OpenAI/Anthropic tool entries."""
    return [t.to_openai_tool() for t in TOOL_DEFINITIONS]


def tool_definitions_as_anthropic_tools() -> list[dict[str, Any]]:
    """Return the tool catalogue in Anthropic's ``tools`` shape."""
    return [
        {
            "name": t.name,
            "description": t.description,
            "input_schema": t.parameters,
        }
        for t in TOOL_DEFINITIONS
    ]


def find_tool(name: str) -> ToolDefinition:
    """Look up a tool by name. Raises ``KeyError`` if it does not exist."""
    for t in TOOL_DEFINITIONS:
        if t.name == name:
            return t
    raise KeyError(f"Unknown tool: {name!r}")


# ---------------------------------------------------------------------------
# Tool dispatcher.
# ---------------------------------------------------------------------------


# Type alias for tool implementations. Each tool takes the raw JSON
# arguments from the agent and returns a JSON-serialisable payload.
ToolImpl = Callable[[dict[str, Any]], dict[str, Any]]


# Dispatch table populated by ``mcp_server.register_tools``. We keep
# the import here so downstream callers can introspect which tools are
# implemented without importing the MCP server itself.
TOOL_IMPLEMENTATIONS: dict[str, ToolImpl] = {}


def invoke_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Dispatch a tool call by name.

    Raises ``KeyError`` for unknown tools, ``TypeError`` for
    implementation errors, ``ValueError`` for invalid arguments. The
    error is returned to the agent as ``{"error": ...}`` by the caller
    (MCP or non-MCP dispatcher).
    """
    impl = TOOL_IMPLEMENTATIONS.get(name)
    if impl is None:
        raise KeyError(f"Tool {name!r} is not registered in this Cancerbero build.")
    return impl(arguments)


def render_tools_manifest() -> str:
    """Return a human-readable manifest of every available tool.

    Used by the ``cancerbero agentic-manifest`` subcommand and exposed
    to the agent in the MCP server's instructions. Machine-readable
    clients should use ``tool_definitions_as_openai_tools`` instead.
    """
    lines = [f"# Cancerbero tool manifest ({len(TOOL_DEFINITIONS)} tools)", ""]
    for tool in TOOL_DEFINITIONS:
        lines.append(f"## `{tool.name}`")
        lines.append("")
        lines.append(tool.description.strip())
        lines.append("")
        params = json.dumps(tool.parameters, indent=2)
        lines.append("**Parameters (JSON Schema):**")
        lines.append("")
        lines.append("```json")
        lines.append(params)
        lines.append("```")
        lines.append("")
    return "\n".join(lines)


__all__ = [
    "CONFIDENCE_VALUES",
    "SEVERITY_VALUES",
    "STATUS_VALUES",
    "TOOL_DEFINITIONS",
    "TOOL_IMPLEMENTATIONS",
    "ToolDefinition",
    "ToolImpl",
    "VERDICT_VALUES",
    "find_tool",
    "invoke_tool",
    "render_tools_manifest",
    "tool_definitions_as_anthropic_tools",
    "tool_definitions_as_openai_tools",
]
