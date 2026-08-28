"""Integration tests for the full check pipeline."""

from __future__ import annotations

import json
from pathlib import Path

from cancerbero.audit import CheckOptions, run_check
from cancerbero.domain import Verdict
from cancerbero.report import canonical_json, render_terminal
from tests.fixtures_factory import write_gguf


class TestModelOnlyCheck:
    def test_valid_model_without_runtime_is_undetermined(self, tmp_path: Path) -> None:
        """Without runtime, the runtime_advisory_join core check is missing → undetermined."""
        path = write_gguf(tmp_path / "model.gguf")
        options = CheckOptions(targets=(path,))
        report = run_check(options, command=["cancerbero", "check", str(path)])
        assert report.verdict is Verdict.UNDETERMINED
        assert report.exit_code == 2
        assert len(report.artifacts) == 1

    def test_terminal_output_has_disclaimer(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "model.gguf")
        options = CheckOptions(targets=(path,))
        report = run_check(options, command=["cancerbero", "check", str(path)])
        text = render_terminal(report)
        assert "not a safety certification" in text

    def test_json_is_deterministic(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "model.gguf")
        options = CheckOptions(targets=(path,))
        report = run_check(options, command=["cancerbero", "check", str(path)])
        j1 = canonical_json(report)
        j2 = canonical_json(report)
        assert j1 == j2
        data = json.loads(j1)
        # Without runtime, verdict is undetermined
        assert data["verdict"] == "undetermined"
        assert "observations" not in data


class TestHashIntegration:
    def test_full_hash_with_expected(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "model.gguf")
        import hashlib

        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        options = CheckOptions(targets=(path,), full_hash=True, expected_sha256=digest)
        report = run_check(options, command=["cancerbero", "check", str(path)])
        # Without runtime, verdict is undetermined even with matching hash
        assert report.verdict is Verdict.UNDETERMINED
        verified = [f for f in report.findings if f.id == "cbr.identity.digest_match"]
        assert len(verified) == 1

    def test_hash_mismatch_produces_not_suitable(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "model.gguf")
        options = CheckOptions(targets=(path,), full_hash=True, expected_sha256="a" * 64)
        report = run_check(options, command=["cancerbero", "check", str(path)])
        assert report.verdict is Verdict.NOT_SUITABLE
        assert report.exit_code == 1


class TestRuntimeIntegration:
    def test_runtime_with_known_build(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "model.gguf")
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        (tmp_path / "build-info.txt").write_text("build = 9500")
        options = CheckOptions(targets=(path,), runtime=binary)
        report = run_check(options, command=["cancerbero", "check", str(path)])
        assert report.verdict is Verdict.SUITABLE
        assert len(report.runtimes) == 1
        assert report.runtimes[0].build == 9500

    def test_vulnerable_runtime_produces_not_suitable(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "model.gguf")
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        (tmp_path / "build-info.txt").write_text("build = 5000")
        options = CheckOptions(targets=(path,), runtime=binary)
        report = run_check(options, command=["cancerbero", "check", str(path)])
        assert report.verdict is Verdict.NOT_SUITABLE
        assert report.exit_code == 1

    def test_unknown_runtime_produces_undetermined(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "model.gguf")
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        options = CheckOptions(targets=(path,), runtime=binary)
        report = run_check(options, command=["cancerbero", "check", str(path)])
        assert report.verdict is Verdict.UNDETERMINED
        assert report.exit_code == 2

    def test_runtime_flags_from_build_info_produce_findings(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "model.gguf")
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        (tmp_path / "build-info.json").write_text('{"build": 8146, "flags": ["--host", "0.0.0.0"]}')
        options = CheckOptions(targets=(path,), runtime=binary)
        report = run_check(options, command=["cancerbero", "check", str(path)])
        flags_findings = [f for f in report.findings if "bind_all_interfaces" in f.id]
        assert len(flags_findings) == 1
        assert flags_findings[0].status.value == "suspicious"


class TestDirectoryCheck:
    def test_directory_with_model_and_runtime(self, tmp_path: Path) -> None:
        write_gguf(tmp_path / "model.gguf")
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        (tmp_path / "build-info.txt").write_text("build = 8146")
        options = CheckOptions(targets=(tmp_path,))
        report = run_check(options, command=["cancerbero", "check", str(tmp_path)])
        assert len(report.artifacts) >= 1
        assert len(report.runtimes) >= 1


class TestMalformedGguf:
    def test_bad_magic_produces_error_finding(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "bad.gguf", bad_magic=True)
        options = CheckOptions(targets=(path,))
        report = run_check(options, command=["cancerbero", "check", str(path)])
        errors = [f for f in report.findings if f.status.value == "error"]
        assert len(errors) >= 1


class TestReportSections:
    def test_report_has_coverage_and_limitations(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "model.gguf")
        options = CheckOptions(targets=(path,))
        report = run_check(options, command=["cancerbero", "check", str(path)])
        data = report.deterministic_dict()
        assert "coverage" in data
        assert "limitations" in data
        assert len(data["limitations"]) > 0
