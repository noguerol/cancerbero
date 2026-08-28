"""Tests for exit codes (task 78)."""

from __future__ import annotations

from pathlib import Path

from cancerbero.audit import CheckOptions, run_check
from cancerbero.domain import Verdict
from tests.fixtures_factory import write_gguf


class TestExitCodes:
    """Task 78: Verify exit codes for each combination of findings, coverage, and errors.

    With the new verdict policy (v0.5), core checks must produce positive evidence
    for SUITABLE. Missing core checks → UNDETERMINED.
    """

    def test_model_without_runtime_is_undetermined(self, tmp_path: Path) -> None:
        """A model without runtime check → undetermined (core check missing)."""
        path = write_gguf(tmp_path / "ok.gguf")
        report = run_check(CheckOptions(targets=(path,)), command=["test"])
        # Without runtime, the runtime_advisory_join core check is missing
        assert report.exit_code == 2
        assert report.verdict is Verdict.UNDETERMINED

    def test_not_suitable_exits_one(self, tmp_path: Path) -> None:
        """A not-suitable model should exit with code 1."""
        path = write_gguf(tmp_path / "model.gguf")
        options = CheckOptions(targets=(path,), full_hash=True, expected_sha256="a" * 64)
        report = run_check(options, command=["test"])
        assert report.exit_code == 1
        assert report.verdict is Verdict.NOT_SUITABLE

    def test_undetermined_exits_two(self, tmp_path: Path) -> None:
        """An undetermined result should exit with code 2."""
        path = write_gguf(tmp_path / "model.gguf")
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        # No build-info.txt → unknown runtime
        options = CheckOptions(targets=(path,), runtime=binary)
        report = run_check(options, command=["test"])
        assert report.exit_code == 2
        assert report.verdict is Verdict.UNDETERMINED

    def test_error_exits_two_or_three(self, tmp_path: Path) -> None:
        """An error condition should exit with code 2 or 3."""
        path = write_gguf(tmp_path / "bad.gguf", bad_magic=True)
        options = CheckOptions(targets=(path,))
        report = run_check(options, command=["test"])
        # Bad magic produces error findings → undetermined
        assert report.exit_code in (2, 3)

    def test_empty_directory_exits_two(self, tmp_path: Path) -> None:
        """An empty directory should exit with code 2 (undetermined)."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        report = run_check(CheckOptions(targets=(empty_dir,)), command=["test"])
        assert report.exit_code == 2

    def test_hash_mismatch_exits_one(self, tmp_path: Path) -> None:
        """A hash mismatch should exit with code 1."""
        path = write_gguf(tmp_path / "model.gguf")
        options = CheckOptions(targets=(path,), full_hash=True, expected_sha256="b" * 64)
        report = run_check(options, command=["test"])
        assert report.exit_code == 1

    def test_vulnerable_runtime_exits_one(self, tmp_path: Path) -> None:
        """A vulnerable runtime should exit with code 1."""
        path = write_gguf(tmp_path / "model.gguf")
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        (tmp_path / "build-info.txt").write_text("build = 5000")
        options = CheckOptions(targets=(path,), runtime=binary)
        report = run_check(options, command=["test"])
        assert report.exit_code == 1

    def test_clean_model_with_runtime_exits_zero(self, tmp_path: Path) -> None:
        """A clean model with a safe runtime should exit with code 0."""
        path = write_gguf(tmp_path / "model.gguf")
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        (tmp_path / "build-info.txt").write_text("build = 9500")
        options = CheckOptions(
            targets=(path,), runtime=binary, runtime_version="9500"
        )
        report = run_check(options, command=["test"])
        assert report.exit_code == 0
        assert report.verdict is Verdict.SUITABLE
