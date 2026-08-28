"""Tests for bounded third-party scanner adapters and routing."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from cancerbero.audit import CheckOptions, run_check
from cancerbero.delegates.base import DelegateLimits, DelegateResult, DelegateRunner
from cancerbero.delegates.fickling import FicklingDelegate
from cancerbero.delegates.modelaudit import ModelAuditDelegate
from cancerbero.delegates.modelscan import ModelScanDelegate
from cancerbero.delegates.picklescan import PickleScanDelegate
from cancerbero.domain import Status
from tests.fixtures_factory import write_gguf


class _FakeDelegate(DelegateRunner):
    name = "fake"
    command = "fake"
    calls: list[Path] = []

    def get_version(self) -> str | None:
        return "1.0"

    def run(self, target: Path, **_: object) -> DelegateResult:
        self.calls.append(target)
        return DelegateResult(
            tool=self.name,
            version="1.0",
            available=True,
            success=True,
            findings=[],
            telemetry_disabled=True,
        )


class TestDelegateRunner:
    def test_environment_does_not_leak_credentials(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANCERBERO_TEST_SECRET", "must-not-leak")
        runner = DelegateRunner()
        runner.command = sys.executable
        returncode, stdout, _, _ = runner._execute(
            [
                sys.executable,
                "-c",
                "import os; print(os.getenv('CANCERBERO_TEST_SECRET', 'absent'))",
            ],
            limits=DelegateLimits(timeout_seconds=10),
        )
        assert returncode == 0
        assert stdout.strip() == "absent"

    def test_captured_output_is_bounded(self) -> None:
        runner = DelegateRunner()
        runner.command = sys.executable
        limit = 1024
        returncode, stdout, stderr, _ = runner._execute(
            [
                sys.executable,
                "-c",
                "import sys; print('x'*100000); print('y'*100000,file=sys.stderr)",
            ],
            limits=DelegateLimits(timeout_seconds=10, max_output_bytes=limit),
        )
        assert returncode == 0
        assert len(stdout.encode()) <= limit
        assert len(stderr.encode()) <= limit
        assert "output truncated" in stdout
        assert "output truncated" in stderr

    def test_timeout_terminates_delegate(self) -> None:
        runner = DelegateRunner()
        runner.command = sys.executable
        returncode, _, stderr, _ = runner._execute(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            limits=DelegateLimits(timeout_seconds=1),
        )
        assert returncode == -1
        assert "Timeout" in stderr

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"timeout_seconds": 0},
            {"max_output_bytes": 0},
            {"max_memory_mb": -1},
        ],
    )
    def test_invalid_limits_are_rejected(self, kwargs: dict[str, int]) -> None:
        with pytest.raises(ValueError):
            DelegateLimits(**kwargs)


class TestDelegateAdapters:
    def test_modelaudit_exit_one_is_successful_finding(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        delegate = ModelAuditDelegate()
        monkeypatch.setattr(delegate, "is_available", lambda: True)
        monkeypatch.setattr(delegate, "get_version", lambda: "0.2.52")
        payload = {
            "issues": [
                {
                    "rule_code": "S201",
                    "severity": "critical",
                    "message": "Dangerous pickle call",
                    "location": "model.pkl",
                }
            ],
            "has_errors": False,
        }
        monkeypatch.setattr(
            delegate,
            "_execute",
            lambda *args, **kwargs: (1, json.dumps(payload), "", 5),
        )
        result = delegate.run(tmp_path / "model.pkl")
        assert result.success
        assert result.findings[0]["id"] == "S201"

    def test_modelscan_parses_preamble_and_finding(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        delegate = ModelScanDelegate()
        monkeypatch.setattr(delegate, "is_available", lambda: True)
        monkeypatch.setattr(delegate, "get_version", lambda: "0.8.8")
        payload = {
            "issues": [
                {
                    "description": "Unsafe operator",
                    "operator": "system",
                    "scanner": "modelscan.scanners.PickleUnsafeOpScan",
                    "severity": "CRITICAL",
                    "source": "model.pkl",
                }
            ],
            "errors": [],
        }
        output = "Using defaults.\n" + json.dumps(payload)
        monkeypatch.setattr(delegate, "_execute", lambda *args, **kwargs: (1, output, "", 5))
        result = delegate.run(tmp_path / "model.pkl")
        assert result.success
        assert result.findings[0]["severity"] == "CRITICAL"

    def test_picklescan_parses_dangerous_import(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        delegate = PickleScanDelegate()
        monkeypatch.setattr(delegate, "is_available", lambda: True)
        output = (
            "/tmp/model.pkl: dangerous import 'posix system' FOUND\n"
            "----------- SCAN SUMMARY -----------\n"
        )
        monkeypatch.setattr(delegate, "_execute", lambda *args, **kwargs: (1, output, "", 5))
        result = delegate.run(tmp_path / "model.pkl")
        assert result.success
        assert result.findings[0]["severity"] == "critical"

    def test_fickling_parses_json_report(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        delegate = FicklingDelegate()
        monkeypatch.setattr(delegate, "is_available", lambda: True)
        monkeypatch.setattr(delegate, "get_version", lambda: "0.1.12")

        def fake_execute(args: list[str], **_: object) -> tuple[int, str, str, int]:
            report_path = Path(args[args.index("--json-output") + 1])
            report_path.write_text(
                json.dumps(
                    {
                        "severity": "LIKELY_OVERTLY_MALICIOUS",
                        "analysis": "Unsafe import",
                        "detailed_results": {},
                    }
                )
            )
            return 1, "", "", 5

        monkeypatch.setattr(delegate, "_execute", fake_execute)
        result = delegate.run(tmp_path / "model.pkl")
        assert result.success
        assert result.findings[0]["severity"] == "critical"


class TestDelegateRouting:
    def test_no_delegate_flag_produces_no_delegate_findings(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "model.gguf")
        report = run_check(CheckOptions(targets=(path,)), command=["test"])
        assert not [finding for finding in report.findings if "delegate" in finding.id]

    def test_all_delegates_routes_only_modelaudit_to_gguf(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import cancerbero.delegates as delegates

        _FakeDelegate.calls = []
        monkeypatch.setattr(delegates, "ModelAuditDelegate", _FakeDelegate)
        monkeypatch.setattr(delegates, "ModelScanDelegate", _FakeDelegate)
        monkeypatch.setattr(delegates, "PickleScanDelegate", _FakeDelegate)
        monkeypatch.setattr(delegates, "FicklingDelegate", _FakeDelegate)
        path = write_gguf(tmp_path / "model.gguf")
        report = run_check(
            CheckOptions(targets=(path,), use_all_delegates=True),
            command=["test"],
        )
        completed = [finding for finding in report.findings if finding.id.endswith("completed")]
        assert len(completed) == 1
        assert completed[0].check == "delegate_modelaudit"

    def test_pickle_target_routes_all_applicable_delegates(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import cancerbero.delegates as delegates

        _FakeDelegate.calls = []
        monkeypatch.setattr(delegates, "ModelAuditDelegate", _FakeDelegate)
        monkeypatch.setattr(delegates, "ModelScanDelegate", _FakeDelegate)
        monkeypatch.setattr(delegates, "PickleScanDelegate", _FakeDelegate)
        monkeypatch.setattr(delegates, "FicklingDelegate", _FakeDelegate)
        path = tmp_path / "model.pkl"
        path.write_bytes(b"not executed")
        report = run_check(
            CheckOptions(targets=(path,), use_all_delegates=True),
            command=["test"],
        )
        completed = [finding for finding in report.findings if finding.id.endswith("completed")]
        assert len(completed) == 4

    def test_delegate_finding_is_suspicious(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import cancerbero.delegates as delegates

        class FindingDelegate(_FakeDelegate):
            def run(self, target: Path, **_: object) -> DelegateResult:
                return DelegateResult(
                    tool="modelaudit",
                    version="1.0",
                    available=True,
                    success=True,
                    findings=[
                        {
                            "id": "S201",
                            "severity": "critical",
                            "message": "Dangerous call",
                            "location": str(target),
                        }
                    ],
                )

        monkeypatch.setattr(delegates, "ModelAuditDelegate", FindingDelegate)
        path = write_gguf(tmp_path / "model.gguf")
        report = run_check(
            CheckOptions(targets=(path,), use_modelaudit=True),
            command=["test"],
        )
        delegate_findings = [
            finding for finding in report.findings if finding.id.startswith("cbr.delegate")
        ]
        assert any(finding.status is Status.SUSPICIOUS for finding in delegate_findings)
