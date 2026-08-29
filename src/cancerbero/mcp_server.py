"""Model Context Protocol server for Cancerbero.

Expose every agent-callable capability as MCP ``tools`` so that
Claude Code, OpenAI Codex CLI, Cursor, and any other MCP-aware client
can drive Cancerbero without writing glue code.

Run the server with::

    cancerbero mcp

It speaks MCP over stdio (the default transport) and can also be
invoked as a one-shot ``tools/call`` for testing::

    python -m cancerbero.mcp_server --invoke cancerbero_list_advisories '{}'

The server registers every ``ToolDefinition`` from
``cancerbero.agentic.schemas`` and wires it to the implementations in
``cancerbero.agentic.dispatch``. The single source of truth lives in
``agentic/schemas.py`` so the MCP tool surface and the
OpenAI/Anthropic function-calling surface cannot drift.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from cancerbero import __version__
from cancerbero.agentic.dispatch import install_dispatch, safe_invoke_tool
from cancerbero.agentic.schemas import (
    TOOL_DEFINITIONS,
    tool_definitions_as_anthropic_tools,
)

SERVER_NAME = "cancerbero"
SERVER_INSTRUCTIONS = (
    "Cancerbero is a local, offline-first security inspection tool for"
    " GGUF artifacts and llama.cpp runtimes. It is read-only, does not"
    " execute models, and does not require network access. Use"
    " ``cancerbero_inspect`` to decide whether a model + runtime are"
    " safe to load, ``cancerbero_check_template`` to vet a chat"
    " template, ``cancerbero_companion_scan`` to audit a model"
    " repository, and ``cancerbero_list_advisories`` to learn what the"
    " current installation can detect. Verdict values: ``suitable``"
    " (every core check passed; exit 0), ``clean`` (no suspicious"
    " findings on the checks performed; exit 0; typically when no"
    " ``--runtime`` was supplied), ``not_suitable`` (a confirmed"
    " risk; exit 1), ``undetermined`` (a check could not complete;"
    " exit 2). Cancerbero never asserts that a model is 'safe' -"
    " it reports what was checked and what was found."
)


def _build_server() -> Any:
    """Construct and configure the FastMCP server."""
    # Imported lazily so a missing ``mcp`` SDK does not break the CLI
    # when the user only wants ``cancerbero check``.
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(
        name=SERVER_NAME,
        instructions=SERVER_INSTRUCTIONS,
        website_url="https://github.com/noguerol/cancerbero",
    )
    install_dispatch()
    for tool in TOOL_DEFINITIONS:
        impl = _make_mcp_tool(tool.name, tool.description, tool.parameters)
        mcp.add_tool(
            impl,
            name=tool.name,
            description=tool.description,
        )
    return mcp


def _make_mcp_tool(name: str, description: str, parameters: dict[str, Any]) -> Any:
    """Wrap a Cancerbero tool for the FastMCP server.

    FastMCP's ``@tool`` / ``add_tool`` expects a real function with
    typed parameters and a docstring from which to derive the JSON
    schema. We expose every Cancerbero tool as a single ``payload``
    argument that the agent fills with the JSON object described in
    ``agentic.schemas.ToolDefinition``. The wrapper hands the payload
    to ``safe_invoke_tool`` and returns the JSON-encoded result so
    the agent receives a stable string.
    """

    def _impl(payload: dict[str, Any] | None = None) -> str:
        """..."""
        result = safe_invoke_tool(name, dict(payload or {}))
        return json.dumps(result, indent=2, sort_keys=True, default=str)

    _impl.__name__ = name
    _impl.__doc__ = (
        f"{description}\n\n"
        f"Parameters: pass a JSON object matching this schema:\n"
        f"```json\n{json.dumps(parameters, indent=2)}\n```"
    )
    return _impl


def run_server() -> int:
    """Entry point for ``cancerbero mcp`` and ``python -m cancerbero.mcp_server``."""
    mcp = _build_server()
    mcp.run()  # blocks; stdio transport by default
    return 0


def invoke_once(name: str, arguments_json: str) -> int:
    """Run a single tool call and print the result to stdout.

    Used by integration tests and the ``--invoke`` CLI flag.
    """
    install_dispatch()
    try:
        arguments = json.loads(arguments_json) if arguments_json else {}
    except json.JSONDecodeError as exc:
        print(
            json.dumps(
                {"error": "invalid_json", "message": str(exc)},
                indent=2,
            ),
            file=sys.stderr,
        )
        return 3
    if not isinstance(arguments, dict):
        print(
            json.dumps(
                {
                    "error": "invalid_arguments",
                    "message": "tool arguments must be a JSON object",
                },
                indent=2,
            ),
            file=sys.stderr,
        )
        return 3
    result = safe_invoke_tool(name, arguments)
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0


def print_manifest() -> int:
    """Print the Anthropic / OpenAI / Markdown tool manifest to stdout."""
    install_dispatch()
    print(f"# {SERVER_NAME} v{__version__}")
    print()
    print(SERVER_INSTRUCTIONS.strip())
    print()
    print("## Tools (Anthropic format)")
    print()
    print(json.dumps(tool_definitions_as_anthropic_tools(), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point used by ``cancerbero mcp``."""
    parser = argparse.ArgumentParser(
        prog="cancerbero-mcp",
        description=(
            "Model Context Protocol server for Cancerbero. Exposes the"
            " same tool catalogue as the JSON-schema surface so MCP"
            " clients can drive the tool natively."
        ),
    )
    parser.add_argument(
        "--invoke",
        metavar="TOOL",
        help=(
            "Run a single tool call instead of starting the server."
            " Pass the tool name and JSON arguments via --args."
        ),
    )
    parser.add_argument(
        "--args",
        default="{}",
        help=("JSON arguments for --invoke. Defaults to an empty object."),
    )
    parser.add_argument(
        "--manifest",
        action="store_true",
        help=(
            "Print the tool manifest (Anthropic format) to stdout and"
            " exit. Useful for agent setup scripts that want a"
            " machine-readable view of the tool catalogue."
        ),
    )
    args = parser.parse_args(argv)

    if args.manifest:
        return print_manifest()
    if args.invoke:
        return invoke_once(args.invoke, args.args)
    return run_server()


if __name__ == "__main__":  # pragma: no cover - script entry point
    raise SystemExit(main())
