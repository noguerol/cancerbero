"""End-to-end integration test: drive the MCP server over stdio.

Spawns the actual ``python -m cancerbero.mcp_server`` process and
performs a real tool call through the MCP client SDK. Catches
schema/serialisation regressions that unit tests cannot."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

from tests.fixtures_factory import write_gguf


@pytest.mark.asyncio
async def test_mcp_stdio_full_protocol():
    """Spawn the MCP server, list tools, call one, receive a JSON string."""
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "cancerbero.mcp_server"],
        env=os.environ.copy(),
    )
    async with stdio_client(server_params) as (read, write), ClientSession(
        read, write
    ) as session:
        await session.initialize()
        tools = await session.list_tools()
        names = {t.name for t in tools.tools}
        assert "cancerbero_inspect" in names
        assert "cancerbero_check_template" in names
        assert "cancerbero_list_advisories" in names

        # Call list_advisories and parse the JSON result.
        result = await session.call_tool("cancerbero_list_advisories", {"payload": {}})
        payload = json.loads(result.content[0].text)
        assert "advisories" in payload
        assert payload["advisory_count"] >= 1

        # Inspect a real GGUF.
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            p = write_gguf(
                tmp / "model.gguf",
                chat_template="{{ messages|length }}",
            )
            result = await session.call_tool(
                "cancerbero_artifact_facts",
                {"payload": {"path": str(p)}},
            )
            payload = json.loads(result.content[0].text)
            assert payload["architecture"] == "llama"
            assert payload["has_chat_template"] is True
