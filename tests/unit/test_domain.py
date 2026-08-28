from pathlib import Path

import pytest

from cancerbero.domain import (
    AuditReport,
    Confidence,
    Finding,
    Severity,
    Status,
    Target,
    TargetKind,
    Verdict,
)


def test_non_suspicious_finding_cannot_claim_high_severity() -> None:
    with pytest.raises(ValueError, match="Only suspicious"):
        Finding(
            id="cbr.invalid",
            head="loading",
            check="example",
            status=Status.CLEAN,
            severity=Severity.HIGH,
        )


def test_report_deterministic_content_excludes_observations() -> None:
    report = AuditReport(
        schema_version="1.0",
        cancerbero_version="0.1.0",
        command=["cancerbero", "check", "x"],
        targets=[Target(Path("x"), TargetKind.UNKNOWN, "test")],
        artifacts=[],
        runtimes=[],
        findings=[
            Finding(
                id="cbr.example",
                head="loading",
                check="example",
                status=Status.NOT_APPLICABLE,
                confidence=Confidence.HIGH,
            )
        ],
        bundle=None,
        verdict=Verdict.SUITABLE,
        exit_code=0,
        observations={"duration_seconds": 5},
    )
    assert "observations" not in report.deterministic_dict()
    assert report.to_dict()["observations"] == {"duration_seconds": 5}
