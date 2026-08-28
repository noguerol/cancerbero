"""Tests for streamed SHA-256 hashing."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from cancerbero.hashing import hash_file, validate_expected_sha256


class TestArtifactHashField:
    """The full-file digest must be written back into ``ArtifactFacts.sha256``."""

    def test_full_hash_populates_artifact_sha256(self, tmp_path: Path) -> None:
        from cancerbero.audit import CheckOptions, run_check
        from tests.fixtures_factory import write_gguf

        path = write_gguf(tmp_path / "model.gguf")
        options = CheckOptions(targets=(path,), full_hash=True)
        report = run_check(options, command=["cancerbero", "check", str(path)])
        assert len(report.artifacts) == 1
        assert report.artifacts[0].sha256 == hashlib.sha256(path.read_bytes()).hexdigest()

    def test_without_full_hash_sha256_stays_unset(self, tmp_path: Path) -> None:
        from cancerbero.audit import CheckOptions, run_check
        from tests.fixtures_factory import write_gguf

        path = write_gguf(tmp_path / "model.gguf")
        options = CheckOptions(targets=(path,))
        report = run_check(options, command=["cancerbero", "check", str(path)])
        assert len(report.artifacts) == 1
        assert report.artifacts[0].sha256 is None

    def test_full_hash_calls_on_hash_complete(self, tmp_path: Path) -> None:
        from cancerbero.audit import CheckOptions, ProgressCallback, run_check
        from tests.fixtures_factory import write_gguf

        path = write_gguf(tmp_path / "model.gguf")
        expected = hashlib.sha256(path.read_bytes()).hexdigest()

        class RecordingProgress(ProgressCallback):
            def __init__(self) -> None:
                self.calls: list[tuple[Path, str]] = []

            def on_hash_complete(self, path: Path, digest: str) -> None:
                self.calls.append((path, digest))

        progress = RecordingProgress()
        options = CheckOptions(targets=(path,), full_hash=True)
        run_check(options, command=["cancerbero", "check", str(path)], progress=progress)
        assert progress.calls == [(path, expected)]


class TestHashFile:
    def test_deterministic(self, tmp_path: Path) -> None:
        path = tmp_path / "test.bin"
        path.write_bytes(b"hello world")
        r1 = hash_file(path)
        r2 = hash_file(path)
        assert r1.digest == r2.digest
        assert r1.bytes_read == 11

    def test_matches_expected(self, tmp_path: Path) -> None:
        path = tmp_path / "test.bin"
        path.write_bytes(b"hello world")
        result = hash_file(
            path, expected="b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        )
        assert result.matches is True

    def test_mismatch_detected(self, tmp_path: Path) -> None:
        path = tmp_path / "test.bin"
        path.write_bytes(b"hello world")
        result = hash_file(path, expected="a" * 64)
        assert result.matches is False

    def test_no_expected_returns_none(self, tmp_path: Path) -> None:
        path = tmp_path / "test.bin"
        path.write_bytes(b"hello world")
        result = hash_file(path)
        assert result.matches is None

    def test_finding_match(self, tmp_path: Path) -> None:
        path = tmp_path / "test.bin"
        path.write_bytes(b"hello world")
        result = hash_file(
            path, expected="b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        )
        finding = result.finding
        assert finding.status.value == "verified"

    def test_finding_mismatch(self, tmp_path: Path) -> None:
        path = tmp_path / "test.bin"
        path.write_bytes(b"hello world")
        result = hash_file(path, expected="a" * 64)
        finding = result.finding
        assert finding.status.value == "suspicious"

    def test_finding_no_expected(self, tmp_path: Path) -> None:
        path = tmp_path / "test.bin"
        path.write_bytes(b"hello world")
        result = hash_file(path)
        finding = result.finding
        assert finding.status.value == "unchecked"


class TestValidateDigest:
    def test_valid_lowercase(self) -> None:
        assert validate_expected_sha256("a" * 64) == "a" * 64

    def test_valid_uppercase_normalized(self) -> None:
        assert validate_expected_sha256("A" * 64) == "a" * 64

    def test_too_short_rejected(self) -> None:
        with pytest.raises(ValueError, match="64"):
            validate_expected_sha256("a" * 63)

    def test_whitespace_rejected(self) -> None:
        with pytest.raises(ValueError, match="64"):
            validate_expected_sha256("a" * 64 + " ")

    def test_non_hex_rejected(self) -> None:
        with pytest.raises(ValueError, match="hexadecimal"):
            validate_expected_sha256("g" * 64)
