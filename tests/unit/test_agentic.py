"""Tests for the agentic surface of Cancerbero.

Covers the JSON-schema tool catalogue, the dispatcher, the MCP server
helper functions, and the end-to-end ``safe_invoke_tool`` path that
agents and the MCP server both call.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cancerbero.agentic import dispatch
from cancerbero.agentic.schemas import (
    SEVERITY_VALUES,
    STATUS_VALUES,
    TOOL_DEFINITIONS,
    VERDICT_VALUES,
    find_tool,
    tool_definitions_as_anthropic_tools,
    tool_definitions_as_openai_tools,
)
from tests.fixtures_factory import write_gguf

# ---------------------------------------------------------------------------
# Catalogue shape.
# ---------------------------------------------------------------------------


class TestToolCatalogue:
    def test_every_tool_has_required_fields(self) -> None:
        for tool in TOOL_DEFINITIONS:
            assert tool.name
            assert tool.description
            assert tool.parameters.get("type") == "object"

    def test_tool_names_are_unique(self) -> None:
        names = [t.name for t in TOOL_DEFINITIONS]
        assert len(names) == len(set(names)), names

    def test_openai_tools_have_function_wrapper(self) -> None:
        tools = tool_definitions_as_openai_tools()
        assert len(tools) == len(TOOL_DEFINITIONS)
        for entry in tools:
            assert entry["type"] == "function"
            assert "function" in entry
            fn = entry["function"]
            assert {"name", "description", "parameters"} <= set(fn)

    def test_anthropic_tools_use_input_schema(self) -> None:
        tools = tool_definitions_as_anthropic_tools()
        assert len(tools) == len(TOOL_DEFINITIONS)
        for entry in tools:
            assert "input_schema" in entry

    def test_verdict_values_are_stable(self) -> None:
        assert set(VERDICT_VALUES) == {"suitable", "not_suitable", "undetermined", "clean"}

    def test_status_values_are_stable(self) -> None:
        assert set(STATUS_VALUES) == {
            "verified",
            "clean",
            "suspicious",
            "unchecked",
            "not_applicable",
            "error",
        }

    def test_severity_values_are_stable(self) -> None:
        assert set(SEVERITY_VALUES) == {"critical", "high", "medium", "low", "info"}

    def test_find_tool_returns_known(self) -> None:
        tool = find_tool("cancerbero_inspect")
        assert tool.name == "cancerbero_inspect"

    def test_find_tool_raises_for_unknown(self) -> None:
        with pytest.raises(KeyError):
            find_tool("not_a_tool")


# ---------------------------------------------------------------------------
# Dispatcher.
# ---------------------------------------------------------------------------


class TestToolDispatcher:
    def setup_method(self) -> None:
        dispatch.install_dispatch()

    def test_cancerbero_inspect_on_clean_gguf(self, tmp_path: Path) -> None:
        path = write_gguf(
            tmp_path / "model.gguf",
            chat_template="hello {{ messages|length }}",
        )
        result = dispatch.safe_invoke_tool(
            "cancerbero_inspect",
            {"targets": [str(path)]},
        )
        assert "error" not in result
        assert result["verdict"] == "clean"
        assert result["exit_code"] == 0
        assert len(result["artifacts"]) == 1
        assert result["artifacts"][0]["architecture"] == "llama"

    def test_cancerbero_inspect_detects_malicious_template(self, tmp_path: Path) -> None:
        path = write_gguf(
            tmp_path / "bad.gguf",
            chat_template="{{ messages[0]['content'] }}{{ os.system('id') }}",
        )
        result = dispatch.safe_invoke_tool("cancerbero_inspect", {"targets": [str(path)]})
        assert "error" not in result
        assert result["verdict"] == "not_suitable"
        suspicious = [f for f in result["findings"] if f["status"] == "suspicious"]
        assert suspicious, result

    def test_cancerbero_inspect_missing_path(self) -> None:
        result = dispatch.safe_invoke_tool(
            "cancerbero_inspect", {"targets": ["/no/such/file.gguf"]}
        )
        assert result["error"] == "io_error"

    def test_cancerbero_inspect_missing_targets(self) -> None:
        result = dispatch.safe_invoke_tool("cancerbero_inspect", {"targets": []})
        assert result["error"] == "invalid_arguments"

    def test_cancerbero_artifact_facts(self, tmp_path: Path) -> None:
        path = write_gguf(
            tmp_path / "m.gguf",
            architecture="llama",
            name="my-model",
        )
        result = dispatch.safe_invoke_tool("cancerbero_artifact_facts", {"path": str(path)})
        assert "error" not in result
        assert result["architecture"] == "llama"
        assert result["name"] == "my-model"
        assert "tensors" in result
        assert "metadata" in result

    def test_cancerbero_artifact_facts_rejects_directory(self, tmp_path: Path) -> None:
        result = dispatch.safe_invoke_tool("cancerbero_artifact_facts", {"path": str(tmp_path)})
        assert result["error"] == "invalid_arguments"

    def test_cancerbero_check_template_clean(self) -> None:
        result = dispatch.safe_invoke_tool(
            "cancerbero_check_template",
            {"template": "{% for m in messages %}{{ m.content }}{% endfor %}"},
        )
        assert "error" not in result
        assert result["verdict"] in ("clean", "suitable")

    def test_cancerbero_check_template_malicious(self) -> None:
        result = dispatch.safe_invoke_tool(
            "cancerbero_check_template",
            {"template": "{{ ''.__class__.__mro__[1].__subclasses__() }}"},
        )
        assert "error" not in result
        assert result["verdict"] == "not_suitable"
        assert any("dangerous_function" in f["id"] for f in result["findings"])

    def test_cancerbero_check_template_rejects_non_string(self) -> None:
        result = dispatch.safe_invoke_tool("cancerbero_check_template", {"template": 1234})
        assert result["error"] == "invalid_arguments"

    def test_cancerbero_companion_scan_clean(self, tmp_path: Path) -> None:
        (tmp_path / "config.json").write_text("{}")
        result = dispatch.safe_invoke_tool(
            "cancerbero_companion_scan", {"directory": str(tmp_path)}
        )
        assert "error" not in result
        assert "findings" in result
        assert "config.json" in result["files_inspected"]

    def test_cancerbero_companion_scan_malicious(self, tmp_path: Path) -> None:
        (tmp_path / "config.json").write_text('{"api_key": "sk-abc123def456ghi789jkl012mno345pqr"}')
        result = dispatch.safe_invoke_tool(
            "cancerbero_companion_scan", {"directory": str(tmp_path)}
        )
        assert "error" not in result
        suspicious = [f for f in result["findings"] if f["status"] == "suspicious"]
        assert suspicious

    def test_cancerbero_companion_scan_missing_directory(self) -> None:
        result = dispatch.safe_invoke_tool(
            "cancerbero_companion_scan", {"directory": "/no/such/dir"}
        )
        assert result["error"] == "io_error"

    def test_cancerbero_list_advisories(self) -> None:
        result = dispatch.safe_invoke_tool("cancerbero_list_advisories", {})
        assert "error" not in result
        assert "advisories" in result
        assert result["advisory_count"] >= 1
        assert result["bundle_version"]
        # Every advisory must carry the documented fields.
        required = {"id", "title", "component", "severity", "affected", "fixed"}
        for advisory in result["advisories"]:
            assert required <= set(advisory), advisory

    def test_cancerbero_hash_matches_expected(self, tmp_path: Path) -> None:
        import hashlib

        path = tmp_path / "blob.bin"
        path.write_bytes(b"hello world")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        result = dispatch.safe_invoke_tool(
            "cancerbero_hash",
            {"path": str(path), "expected": digest},
        )
        assert "error" not in result
        assert result["sha256"] == digest
        assert result["match"] is True

    def test_cancerbero_hash_detects_mismatch(self, tmp_path: Path) -> None:
        path = tmp_path / "blob.bin"
        path.write_bytes(b"hello world")
        result = dispatch.safe_invoke_tool(
            "cancerbero_hash",
            {"path": str(path), "expected": "0" * 64},
        )
        assert "error" not in result
        assert result["match"] is False

    def test_cancerbero_hash_rejects_invalid_digest(self, tmp_path: Path) -> None:
        path = tmp_path / "blob.bin"
        path.write_bytes(b"x")
        result = dispatch.safe_invoke_tool(
            "cancerbero_hash",
            {"path": str(path), "expected": "not-a-digest"},
        )
        assert result["error"] == "invalid_arguments"

    def test_safe_invoke_tool_unknown_tool(self) -> None:
        result = dispatch.safe_invoke_tool("does_not_exist", {})
        assert "error" in result
        assert "unknown_tool" in result["error"]

    def test_safe_invoke_tool_internal_error(self, tmp_path: Path, monkeypatch) -> None:
        # Force an internal error by patching ``load_bundle`` to raise.
        from cancerbero.agentic import dispatch as dispatch_mod

        def boom(_: dict) -> dict:
            raise RuntimeError("boom")

        monkeypatch.setitem(dispatch_mod.TOOL_DISPATCH, "explode", boom)
        result = dispatch.safe_invoke_tool("explode", {})
        assert result["error"] == "internal_error"
        assert "boom" in result["message"]


# ---------------------------------------------------------------------------
# Manifest rendering.
# ---------------------------------------------------------------------------


class TestManifest:
    def test_render_includes_every_tool(self) -> None:
        from cancerbero.agentic.schemas import render_tools_manifest

        text = render_tools_manifest()
        for tool in TOOL_DEFINITIONS:
            assert f"`{tool.name}`" in text


# ---------------------------------------------------------------------------
# MCP server helpers.
# ---------------------------------------------------------------------------


class TestMcpServerHelpers:
    def test_invoke_once_prints_result(self, tmp_path: Path, capsys) -> None:
        from cancerbero.mcp_server import invoke_once

        path = write_gguf(tmp_path / "m.gguf")
        exit_code = invoke_once(
            "cancerbero_artifact_facts",
            json.dumps({"path": str(path)}),
        )
        assert exit_code == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["architecture"] == "llama"

    def test_invoke_once_rejects_bad_json(self, capsys) -> None:
        from cancerbero.mcp_server import invoke_once

        exit_code = invoke_once("cancerbero_list_advisories", "{not valid")
        assert exit_code == 3
        err = capsys.readouterr().err
        assert "invalid_json" in err

    def test_invoke_once_rejects_non_object_args(self, capsys) -> None:
        from cancerbero.mcp_server import invoke_once

        exit_code = invoke_once("cancerbero_list_advisories", "[1, 2, 3]")
        assert exit_code == 3
        err = capsys.readouterr().err
        assert "invalid_arguments" in err

    def test_print_manifest_outputs_anthropic_format(self, capsys) -> None:
        from cancerbero.mcp_server import print_manifest

        exit_code = print_manifest()
        assert exit_code == 0
        out = capsys.readouterr().out
        # Find the JSON tool catalogue section.
        assert '"name": "cancerbero_inspect"' in out

    def test_mcp_server_builds(self) -> None:
        pytest.importorskip("mcp")
        from cancerbero.mcp_server import _build_server

        mcp = _build_server()
        # FastMCP exposes the registered tools; we just check the
        # server constructed without raising.
        assert mcp is not None
