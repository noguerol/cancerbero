"""Tests for llama.cpp runtime inspection."""

from __future__ import annotations

from pathlib import Path

import pytest

from cancerbero.domain import Confidence
from cancerbero.runtime.inspector import RuntimeInspectionError, inspect_runtime


class TestExplicitOverride:
    def test_build_override(self, tmp_path: Path) -> None:
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        facts = inspect_runtime(binary, version_override="b8146")
        assert facts.build == 8146
        assert facts.detection_method == "explicit_override"
        assert facts.confidence is Confidence.HIGH

    def test_version_override(self, tmp_path: Path) -> None:
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        facts = inspect_runtime(binary, version_override="v0.1.0")
        assert facts.version == "0.1.0"

    def test_commit_override(self, tmp_path: Path) -> None:
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        facts = inspect_runtime(binary, version_override="abc1234")
        assert facts.commit == "abc1234"


class TestNearbyBuildFile:
    def test_build_info_json(self, tmp_path: Path) -> None:
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        (tmp_path / "build-info.json").write_text('{"build": 8040, "commit": "abc1234"}')
        facts = inspect_runtime(binary)
        assert facts.build == 8040
        assert facts.detection_method == "nearby_build_file"

    def test_build_info_txt(self, tmp_path: Path) -> None:
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        (tmp_path / "build-info.txt").write_text("build = 7500 (deadbeef12345678)")
        facts = inspect_runtime(binary)
        assert facts.build == 7500
        assert facts.commit == "deadbeef12345678"


class TestGitMetadata:
    def test_git_commit(self, tmp_path: Path) -> None:
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "HEAD").write_text("a" * 40)
        facts = inspect_runtime(binary)
        assert facts.commit == "a" * 40
        assert facts.detection_method == "git_metadata"


class TestStaticBinary:
    def test_version_in_binary(self, tmp_path: Path) -> None:
        binary = tmp_path / "llama-cli"
        binary.write_bytes(
            b"\x7fELF" + b"\x00" * 10 + b"version: 8040 (abc1234)\x00" + b"\x00" * 100
        )
        binary.chmod(0o755)
        facts = inspect_runtime(binary)
        assert facts.build == 8040
        assert facts.detection_method == "static_binary_strings"


class TestBuildInfoFlags:
    """Runtime flags inferred from nearby build-info files."""

    def test_flags_from_json_build_info(self, tmp_path: Path) -> None:
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        (tmp_path / "build-info.json").write_text(
            '{"build": 8040, "flags": ["--host", "0.0.0.0", "--port", "8080"]}'
        )
        facts = inspect_runtime(binary)
        assert facts.flags == ("--host", "0.0.0.0", "--port", "8080")

    def test_flags_ignored_when_not_string_list(self, tmp_path: Path) -> None:
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        (tmp_path / "build-info.json").write_text('{"build": 8040, "flags": "--host"}')
        facts = inspect_runtime(binary)
        assert facts.flags == ()

    def test_flags_from_text_build_info(self, tmp_path: Path) -> None:
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        (tmp_path / "build-info.txt").write_text(
            "build = 7500\nflags: --host 0.0.0.0 --api-key sk-1234\n"
        )
        facts = inspect_runtime(binary)
        assert facts.flags == ("--host", "0.0.0.0", "--api-key", "sk-1234")

    def test_no_flags_by_default(self, tmp_path: Path) -> None:
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        facts = inspect_runtime(binary)
        assert facts.flags == ()

    def test_flags_included_in_dict(self, tmp_path: Path) -> None:
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        (tmp_path / "build-info.json").write_text('{"flags": ["--host", "0.0.0.0"]}')
        facts = inspect_runtime(binary)
        assert facts.to_dict()["flags"] == ["--host", "0.0.0.0"]


class TestExecutableFormat:
    def test_elf(self, tmp_path: Path) -> None:
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        facts = inspect_runtime(binary)
        assert facts.executable_format == "ELF"

    def test_pe(self, tmp_path: Path) -> None:
        binary = tmp_path / "llama-cli.exe"
        # Minimal PE: MZ header with PE offset at 60
        header = b"MZ" + b"\x00" * 58
        header += (64).to_bytes(4, "little")  # PE header offset
        header += b"\x00" * (64 - len(header))
        header += b"PE\x00\x00"
        binary.write_bytes(header + b"\x00" * 100)
        binary.chmod(0o755)
        facts = inspect_runtime(binary)
        assert facts.executable_format == "PE"


class TestPermissions:
    def test_writable_by_others(self, tmp_path: Path) -> None:
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o777)
        facts = inspect_runtime(binary)
        assert facts.writable_by_others is True

    def test_not_writable_by_others(self, tmp_path: Path) -> None:
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        facts = inspect_runtime(binary)
        assert facts.writable_by_others is False


class TestErrors:
    def test_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(RuntimeInspectionError, match="does not exist"):
            inspect_runtime(tmp_path / "nope")

    def test_directory_raises(self, tmp_path: Path) -> None:
        with pytest.raises(RuntimeInspectionError, match="not a regular file"):
            inspect_runtime(tmp_path)
