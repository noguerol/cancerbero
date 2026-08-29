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


class TestFlagPlacement:
    """Regression tests for M5: --no-* flags work in any position."""

    def test_no_interactive_before_subcommand(self, tmp_path: Path) -> None:
        from cancerbero.cli import parse_known_args

        args = parse_known_args(["--no-interactive", "check", str(tmp_path / "x.gguf")])
        assert args.no_interactive is True

    def test_no_interactive_after_subcommand(self, tmp_path: Path) -> None:
        from cancerbero.cli import parse_known_args

        args = parse_known_args(["check", "--no-interactive", str(tmp_path / "x.gguf")])
        assert args.no_interactive is True

    def test_no_color_before_and_after(self, tmp_path: Path) -> None:
        from cancerbero.cli import parse_known_args

        a1 = parse_known_args(["--no-color", "check", str(tmp_path / "x.gguf")])
        a2 = parse_known_args(["check", "--no-color", str(tmp_path / "x.gguf")])
        assert a1.no_color is True
        assert a2.no_color is True

    def test_no_banner_before_and_after(self, tmp_path: Path) -> None:
        from cancerbero.cli import parse_known_args

        a1 = parse_known_args(["--no-banner", "check", str(tmp_path / "x.gguf")])
        a2 = parse_known_args(["check", "--no-banner", str(tmp_path / "x.gguf")])
        assert a1.no_banner is True
        assert a2.no_banner is True
