"""Example: drive Cancerbero through the official MCP Python client.

Spawns the ``cancerbero mcp`` server over stdio and uses the
official ``mcp`` Python SDK to list tools and call them.

Requirements:

    pip install mcp
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# Add the in-tree cancerbero checkout to PATH so ``cancerbero`` is
# resolvable on stdio. Adjust for your environment.
sys.path.insert(0, str(ROOT / "src"))

from tests.fixtures_factory import write_gguf


async def main() -> None:
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "cancerbero.mcp_server"],
        env=env,
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. Discover tools.
            tools = await session.list_tools()
            print(f"Server exposes {len(tools.tools)} tools:")
            for tool in tools.tools:
                print(f"  - {tool.name}: {tool.description[:60]}...")

            # 2. Call one with a real artifact.
            with __import__("tempfile").TemporaryDirectory() as d:
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
                print(
                    f"\nArtifact: {payload['name']} ({payload['architecture']})"
                )
                print(f"Tensors: {payload['tensor_count']}")
                print(f"Has chat template: {payload['has_chat_template']}")


if __name__ == "__main__":
    asyncio.run(main())
