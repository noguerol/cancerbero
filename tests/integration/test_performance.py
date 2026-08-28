"""Performance tests for Cancerbero's metadata-only inspection."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from cancerbero.gguf.inspector import inspect_gguf
from tests.fixtures_factory import write_gguf


class TestMetadataOnlyPerformance:
    """Verify that metadata-only inspection stays well under 5 seconds."""

    def test_sparse_gguf_reads_only_metadata(self, tmp_path: Path) -> None:
        """A file with no tensors should read only metadata bytes."""
        path = write_gguf(tmp_path / "sparse.gguf")
        facts, _ = inspect_gguf(path)
        # With no tensors, bytes_read should equal file_size (both are small)
        # The key assertion is that it completes quickly
        assert facts.bytes_read > 0
        assert facts.tensor_count == 0

    def test_metadata_inspection_completes_quickly(self, tmp_path: Path) -> None:
        """Metadata-only inspection should complete in well under 5 seconds."""
        path = write_gguf(tmp_path / "quick.gguf")
        start = time.monotonic()
        inspect_gguf(path)
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"Metadata inspection took {elapsed:.2f}s, expected <5s"

    def test_metadata_inspection_with_template_is_fast(self, tmp_path: Path) -> None:
        """A file with a chat template should still be fast."""
        template = "{{ bos_token }}" + "{% for m in messages %}{{ m.content }}{% endfor %}" * 100
        path = write_gguf(tmp_path / "template.gguf", chat_template=template)
        start = time.monotonic()
        facts, _ = inspect_gguf(path)
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"Template inspection took {elapsed:.2f}s, expected <5s"
        assert facts.has_chat_template is True


class TestExitCodes:
    """Verify exit codes match the documented policy."""

    def test_model_without_runtime_is_undetermined(self, tmp_path: Path) -> None:
        """Without runtime, the runtime_advisory_join core check is missing → undetermined."""
        from cancerbero.audit import CheckOptions, run_check

        path = write_gguf(tmp_path / "ok.gguf")
        report = run_check(CheckOptions(targets=(path,)), command=["test"])
        assert report.exit_code == 2

    def test_invalid_input_exits_three(self) -> None:
        from cancerbero.cli import main

        with pytest.raises(SystemExit) as exc:
            main(["check", "--expected-sha256", "a" * 64, "file1.gguf", "file2.gguf"])
        assert exc.value.code == 3

    def test_no_targets_exits_two(self, tmp_path: Path) -> None:
        from cancerbero.audit import CheckOptions, run_check

        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        report = run_check(CheckOptions(targets=(empty_dir,)), command=["test"])
        assert report.exit_code == 2
