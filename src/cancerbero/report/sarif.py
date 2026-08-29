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


def _finding_to_sarif_result(
    finding: Finding, *, artifact_uri: str | None = None
) -> dict[str, Any]:
    """Convert a Cancerbero finding to a SARIF result.

    SARIF 2.1.0 requires every result to carry a ``locations`` array (even
    if the location is logical rather than physical) so consumers like
    GitHub Code Scanning can associate the result with a file. We map
    the artifact path to a physical location when we have it; otherwise
    we emit a logical location anchored at the finding id so the result
    is never silently dropped.

    Fixes carry a single ``artifactChanges`` entry pointing at the same
    artifact, with the finding summary as a description.
    """
    location: dict[str, Any]
    if artifact_uri:
        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": artifact_uri},
            }
        }
    else:
        location = {
            "logicalLocation": {
                "name": finding.id,
                "kind": "result",
            }
        }

    result: dict[str, Any] = {
        "ruleId": finding.id,
        "level": _sarif_level(finding.severity.value),
        "message": {
            "text": finding.summary or finding.id,
        },
        "locations": [location],
        "properties": {
            "status": finding.status.value,
            "confidence": finding.confidence.value,
            "head": finding.head,
            "check": finding.check,
        },
    }

    if finding.action:
        change_artifact: dict[str, Any] = {
            "artifactLocation": {"uri": artifact_uri}
            if artifact_uri
            else {"uri": "cancerbero://finding"},
        }
        result["fixes"] = [
            {
                "description": {"text": finding.action},
                "artifactChanges": [change_artifact],
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
                        "informationUri": "https://github.com/noguerol/cancerbero",
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

    # Index artifacts by path so each result carries a physical location
    # pointing at the inspected GGUF file (SARIF 2.1.0 requires locations).
    artifact_uri_by_path: dict[str, str] = {
        str(artifact.path): str(artifact.path) for artifact in report.artifacts
    }

    # Add rules
    seen_rules: set[str] = set()
    for finding in report.findings:
        if finding.id not in seen_rules:
            driver["rules"].append(_finding_to_sarif_rule(finding))
            seen_rules.add(finding.id)

    # Add results (only suspicious and error findings). Each result carries
    # a location pointing at the artifact the finding was emitted against,
    # so GitHub Code Scanning can map it to a file in the repository.
    for finding in report.findings:
        if finding.status in {Status.SUSPICIOUS, Status.ERROR}:
            artifact_uri = None
            evidence_path = (
                finding.evidence.get("path") if isinstance(finding.evidence, dict) else None
            )
            if isinstance(evidence_path, str) and evidence_path in artifact_uri_by_path:
                artifact_uri = artifact_uri_by_path[evidence_path]
            elif report.artifacts:
                artifact_uri = str(report.artifacts[0].path)
            result = _finding_to_sarif_result(finding, artifact_uri=artifact_uri)
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
