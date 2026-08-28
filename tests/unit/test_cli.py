from __future__ import annotations

import json
from pathlib import Path

import pytest

from cancerbero.cli import main
from cancerbero.domain import AuditReport, Verdict


def test_help_is_available_without_loading_audit_engine(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as result:
        main(["check", "--help"])
    assert result.value.code == 0
    assert "without loading the model" in capsys.readouterr().out


def test_invalid_option_combination_uses_operational_exit_code() -> None:
    with pytest.raises(SystemExit) as result:
        main(["check", "model.gguf", "--runtime-version", "b1"])
    assert result.value.code == 3


def test_json_stdout_does_not_mix_terminal_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    report = AuditReport(
        schema_version="1.0",
        cancerbero_version="0.1.0",
        command=[],
        targets=[],
        artifacts=[],
        runtimes=[],
        findings=[],
        bundle=None,
        verdict=Verdict.SUITABLE,
        exit_code=0,
    )
    monkeypatch.setattr(
        "cancerbero.audit.run_check",
        lambda options, command, progress=None: report,
    )
    code = main(["check", str(Path("model.gguf")), "--json", "-"])
    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["verdict"] == "suitable"
    assert "Cancerbero — SUITABLE" in captured.err
