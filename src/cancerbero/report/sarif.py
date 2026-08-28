"""SARIF (Static Analysis Results Interchange Format) output for Cancerbero."""

from __future__ import annotations

import json
from typing import Any

from cancerbero.domain import AuditReport, Finding, Status


def _sarif_level(severity: str) -> str:
    """Map Cancerbero severity to SARIF level."""
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "none",
    }.get(severity, "none")


def _sarif_status(status: Status) -> str:
    """Map Cancerbero status to SARIF result kind."""
    if status is Status.SUSPICIOUS:
        return "fail"
    if status in {Status.VERIFIED, Status.CLEAN}:
        return "pass"
    return "review"


def _finding_to_sarif_result(finding: Finding) -> dict[str, Any]:
    """Convert a Cancerbero finding to a SARIF result."""
    result: dict[str, Any] = {
        "ruleId": finding.id,
        "level": _sarif_level(finding.severity.value),
        "message": {
            "text": finding.summary or finding.id,
        },
        "properties": {
            "status": finding.status.value,
            "confidence": finding.confidence.value,
            "head": finding.head,
            "check": finding.check,
        },
    }

    if finding.action:
        result["fixes"] = [
            {
                "description": {
                    "text": finding.action,
                },
            }
        ]

    if finding.references:
        result["ruleIndex"] = 0  # Will be set properly in the rules array

    return result


def _finding_to_sarif_rule(finding: Finding) -> dict[str, Any]:
    """Convert a Cancerbero finding to a SARIF rule definition."""
    rule: dict[str, Any] = {
        "id": finding.id,
        "shortDescription": {
            "text": finding.summary or finding.id,
        },
        "fullDescription": {
            "text": finding.summary or finding.id,
        },
        "defaultConfiguration": {
            "level": _sarif_level(finding.severity.value),
        },
        "properties": {
            "tags": [finding.head, finding.check],
        },
    }

    if finding.references:
        rule["helpUri"] = finding.references[0]

    return rule


def render_sarif(report: AuditReport) -> str:
    """Render the report as SARIF 2.1.0 for GitHub Code Scanning."""
    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Cancerbero",
                        "version": report.cancerbero_version,
                        "informationUri": "https://github.com/cancerbero-security/cancerbero",
                        "semanticVersion": report.cancerbero_version,
                        "rules": [],
                    },
                },
                "results": [],
                "properties": {
                    "verdict": report.verdict.value,
                    "schema_version": report.schema_version,
                    "command": report.command,
                },
            }
        ],
    }

    run = sarif["runs"][0]
    driver = run["tool"]["driver"]

    # Add rules
    seen_rules: set[str] = set()
    for finding in report.findings:
        if finding.id not in seen_rules:
            driver["rules"].append(_finding_to_sarif_rule(finding))
            seen_rules.add(finding.id)

    # Add results (only suspicious and error findings)
    for finding in report.findings:
        if finding.status in {Status.SUSPICIOUS, Status.ERROR}:
            result = _finding_to_sarif_result(finding)
            # Find rule index
            for i, rule in enumerate(driver["rules"]):
                if rule["id"] == finding.id:
                    result["ruleIndex"] = i
                    break
            run["results"].append(result)

    # Add artifact info
    if report.artifacts:
        run["artifacts"] = []
        for artifact in report.artifacts:
            sarif_artifact: dict[str, Any] = {
                "location": {
                    "uri": str(artifact.path),
                },
                "properties": {
                    "format": "gguf",
                    "version": artifact.gguf_version,
                    "architecture": artifact.architecture,
                    "tensor_count": artifact.tensor_count,
                },
            }
            run["artifacts"].append(sarif_artifact)

    # Add invocation
    run["invocations"] = [
        {
            "commandLine": " ".join(report.command),
            "executionSuccessful": report.exit_code < 3,
            "exitCode": report.exit_code,
        }
    ]

    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


__all__ = ["render_sarif"]
