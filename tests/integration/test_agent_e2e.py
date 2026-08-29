"""End-to-end driver: spawn the MCP server, call every tool, verify.

Used as the final regression test for the agentic layer. Drives the
real ``cancerbero mcp`` subprocess via the official MCP Python
client SDK, calls every public tool, and asserts the JSON shapes
match the documented contract.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

from tests.fixtures_factory import write_gguf


@pytest.mark.asyncio
async def test_every_public_tool_round_trip() -> None:
    """Spawn the MCP server and call every public tool."""
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
        expected = {
            "cancerbero_inspect",
            "cancerbero_artifact_facts",
            "cancerbero_check_template",
            "cancerbero_companion_scan",
            "cancerbero_list_advisories",
            "cancerbero_hash",
            "cancerbero_self_test",
        }
        assert expected <= names, names

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            # Use two separate directories: one for the clean
            # cancerbero_inspect call (no companion signals) and
            # one for the malicious cancerbero_companion_scan test.
            clean_dir = tmp / "clean"
            clean_dir.mkdir()
            (clean_dir / "config.json").write_text("{}")
            clean_model = write_gguf(
                clean_dir / "model.gguf",
                chat_template="{% for m in messages %}{{ m.content }}{% endfor %}",
            )

            companion_dir = tmp / "repo"
            companion_dir.mkdir()
            (companion_dir / "config.json").write_text(
                '{"trust_remote_code": true, "auto_map": {"x": "y"}}'
            )

            # 1. cancerbero_inspect -- no runtime => CLEAN.
            r = await session.call_tool(
                "cancerbero_inspect", {"payload": {"targets": [str(clean_model)]}}
            )
            payload = json.loads(r.content[0].text)
            assert payload["verdict"] == "clean"
            assert payload["exit_code"] == 0
            assert len(payload["artifacts"]) == 1

            # 2. cancerbero_artifact_facts -- fast lookup.
            r = await session.call_tool(
                "cancerbero_artifact_facts", {"payload": {"path": str(clean_model)}}
            )
            payload = json.loads(r.content[0].text)
            assert payload["architecture"] == "llama"
            assert "tensors" in payload
            assert "metadata" in payload

            # 3. cancerbero_check_template -- benign.
            r = await session.call_tool(
                "cancerbero_check_template",
                {"payload": {"template": "{% for m in messages %}{{ m.content }}{% endfor %}"}},
            )
            payload = json.loads(r.content[0].text)
            assert payload["verdict"] in ("clean", "suitable")

            # 3b. cancerbero_check_template -- malicious.
            r = await session.call_tool(
                "cancerbero_check_template",
                {
                    "payload": {
                        "template": (
                            "{{ ''.__class__.__mro__[1]"
                            ".__subclasses__() }}"
                        )
                    }
                },
            )
            payload = json.loads(r.content[0].text)
            assert payload["verdict"] == "not_suitable"
            assert any(
                "dangerous_function" in f["id"]
                for f in payload["findings"]
            )

            # 4. cancerbero_companion_scan -- malicious directory.
            r = await session.call_tool(
                "cancerbero_companion_scan",
                {"payload": {"directory": str(companion_dir)}},
            )
            payload = json.loads(r.content[0].text)
            assert "findings" in payload
            assert any(
                f["status"] == "suspicious" for f in payload["findings"]
            )

            # 5. cancerbero_list_advisories.
            r = await session.call_tool(
                "cancerbero_list_advisories", {"payload": {}}
            )
            payload = json.loads(r.content[0].text)
            assert payload["advisory_count"] >= 1
            assert "advisories" in payload
            assert payload["bundle_version"]

            # 6. cancerbero_hash -- match and mismatch.
            r = await session.call_tool(
                "cancerbero_hash",
                {"payload": {"path": str(clean_model)}},
            )
            payload = json.loads(r.content[0].text)
            assert "sha256" in payload
            assert payload["match"] is None
            digest = payload["sha256"]

            r = await session.call_tool(
                "cancerbero_hash",
                {"payload": {"path": str(clean_model), "expected": digest}},
            )
            payload = json.loads(r.content[0].text)
            assert payload["match"] is True

            # 7. cancerbero_self_test -- returns aggregate counts.
            r = await session.call_tool(
                "cancerbero_self_test", {"payload": {}}
            )
            payload = json.loads(r.content[0].text)
            assert {
                "true_positives",
                "true_negatives",
                "false_positives",
                "false_negatives",
            } <= set(payload)
