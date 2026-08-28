"""Tests for target discovery."""

from __future__ import annotations

from pathlib import Path

from cancerbero.discovery import (
    classify_target,
    discover_directory,
    discover_targets,
    has_gguf_magic,
    is_known_llama_cpp_name,
)
from cancerbero.domain import TargetKind
from tests.fixtures_factory import write_gguf


class TestGgufDetection:
    def test_gguf_detected_by_magic(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "model.gguf")
        assert has_gguf_magic(path) is True

    def test_non_gguf_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "not.gguf"
        path.write_bytes(b"NOTG" + b"\x00" * 100)
        assert has_gguf_magic(path) is False

    def test_empty_file_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.gguf"
        path.write_bytes(b"")
        assert has_gguf_magic(path) is False

    def test_gguf_without_extension_detected(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "model")
        target = classify_target(path)
        assert target.kind is TargetKind.GGUF


class TestLlamaCppDetection:
    def test_known_names(self) -> None:
        assert is_known_llama_cpp_name("llama-cli") is True
        assert is_known_llama_cpp_name("llama-server") is True
        assert is_known_llama_cpp_name("llama-cli.exe") is True
        assert is_known_llama_cpp_name("random-binary") is False
        assert is_known_llama_cpp_name("main") is False


class TestClassifyTarget:
    def test_directory_classified(self, tmp_path: Path) -> None:
        target = classify_target(tmp_path)
        assert target.kind is TargetKind.DIRECTORY

    def test_nonexistent_classified(self, tmp_path: Path) -> None:
        target = classify_target(tmp_path / "nope")
        assert target.kind is TargetKind.UNKNOWN

    def test_symlink_not_followed(self, tmp_path: Path) -> None:
        real = write_gguf(tmp_path / "real.gguf")
        link = tmp_path / "link.gguf"
        link.symlink_to(real)
        target = classify_target(link)
        assert target.kind is TargetKind.UNKNOWN


class TestDirectoryDiscovery:
    def test_finds_gguf_and_runtime(self, tmp_path: Path) -> None:
        write_gguf(tmp_path / "model.gguf")
        (tmp_path / "llama-cli").write_bytes(b"\x7fELF" + b"\x00" * 100)
        result = discover_directory(tmp_path)
        kinds = {t.kind for t in result.targets}
        assert TargetKind.GGUF in kinds
        assert TargetKind.LLAMA_CPP_RUNTIME in kinds
        assert result.complete is True

    def test_ignores_symlinks(self, tmp_path: Path) -> None:
        real = write_gguf(tmp_path / "real.gguf")
        link = tmp_path / "link.gguf"
        link.symlink_to(real)
        result = discover_directory(tmp_path)
        assert result.skipped_symlinks >= 1
        assert all(t.path.name != "link.gguf" for t in result.targets)

    def test_ignores_venv(self, tmp_path: Path) -> None:
        venv = tmp_path / ".venv"
        venv.mkdir()
        write_gguf(venv / "model.gguf")
        result = discover_directory(tmp_path)
        assert all(t.path.parent != venv for t in result.targets)

    def test_respects_candidate_limit(self, tmp_path: Path) -> None:
        from cancerbero.gguf.limits import ParserLimits

        for i in range(5):
            (tmp_path / f"file{i}.txt").write_bytes(b"x")
        result = discover_directory(tmp_path, limits=ParserLimits(max_directory_candidates=3))
        assert result.candidates_examined <= 3
        assert result.limit_reached is True


class TestDiscoverTargets:
    def test_explicit_file(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "model.gguf")
        result = discover_targets([path])
        assert len(result.targets) == 1
        assert result.targets[0].kind is TargetKind.GGUF
