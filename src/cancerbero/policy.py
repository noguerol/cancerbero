"""Verdict and exit-code policy for Cancerbero findings."""

from __future__ import annotations

from cancerbero.domain import Confidence, Finding, Severity, Status, Verdict

# Core checks that must produce positive evidence for a SUITABLE verdict.
# If any core check is missing (unchecked/error), the verdict is UNDETERMINED.
# This prevents the "SUITABLE on no evidence" problem.
_CORE_CHECKS: frozenset[str] = frozenset(
    {
        "gguf_structure",  # GGUF parsed successfully
        "chat_template_static",  # Template analyzed (present or absent)
        "runtime_advisory_join",  # Runtime version identified and checked
    }
)


def _should_block(severity: Severity, classification: Confidence) -> bool:
    """Determine if a finding should block SUITABLE verdict.

    Matrix:
    |                    | Classification HIGH | Classification MEDIUM | Classification LOW |
    |--------------------|--------------------|-----------------------|-------------------|
    | Severity CRITICAL  | BLOCK              | BLOCK                 | UNDETERMINED      |
    | Severity HIGH      | BLOCK              | UNDETERMINED          | informational     |
    | Severity MEDIUM/LOW| UNDETERMINED       | informational         | informational     |
    """
    if severity is Severity.CRITICAL:
        return classification in {Confidence.HIGH, Confidence.MEDIUM}
    if severity is Severity.HIGH:
        return classification is Confidence.HIGH
    return False


def _should_undetermined(severity: Severity, classification: Confidence) -> bool:
    """Determine if a finding should produce UNDETERMINED verdict."""
    if severity is Severity.CRITICAL:
        return classification is Confidence.LOW
    if severity is Severity.HIGH:
        return classification is Confidence.MEDIUM
    if severity in {Severity.MEDIUM, Severity.LOW}:
        return classification is Confidence.HIGH
    return False


def evaluate_verdict(findings: tuple[Finding, ...]) -> tuple[Verdict, int]:
    """Determine the verdict and exit code from a set of findings.

    Policy:
    - Severity × Classification matrix determines blocking
    - Core checks must have positive evidence for SUITABLE
    - Missing core checks → UNDETERMINED

    Core checks are: gguf_structure, chat_template_static, runtime_advisory_join.
    Without positive evidence from these, we cannot say "suitable".
    """
    should_block = False
    should_undetermined = False
    has_mandatory_gap = False
    completed_checks: set[str] = set()
    gap_checks: set[str] = set()

    # Track findings per check for core check evaluation
    check_statuses: dict[str, list[Status]] = {}

    for finding in findings:
        # Track which checks produced positive evidence
        # NOT_APPLICABLE counts as positive (check was performed, determined N/A)
        if finding.status in {Status.VERIFIED, Status.CLEAN, Status.NOT_APPLICABLE}:
            completed_checks.add(finding.check)

        # Apply severity × classification matrix
        if finding.status is Status.SUSPICIOUS:
            if _should_block(finding.severity, finding.classification):
                should_block = True
            elif _should_undetermined(finding.severity, finding.classification):
                should_undetermined = True

        # Track mandatory gaps (only for non-core checks)
        if (
            finding.mandatory
            and finding.status in {Status.UNCHECKED, Status.ERROR}
            and finding.check not in _CORE_CHECKS
        ):
            has_mandatory_gap = True

        # Track statuses per check for core check evaluation
        if finding.check in _CORE_CHECKS:
            if finding.check not in check_statuses:
                check_statuses[finding.check] = []
            check_statuses[finding.check].append(finding.status)

    # For core checks: only count as gap if ALL findings for that check are unchecked/error
    # If at least one finding is verified/clean/not_applicable, the check has positive evidence
    for check in _CORE_CHECKS:
        if check in check_statuses:
            statuses = check_statuses[check]
            has_positive = any(
                s in {Status.VERIFIED, Status.CLEAN, Status.NOT_APPLICABLE} for s in statuses
            )
            if not has_positive:
                gap_checks.add(check)

    # Check for missing core checks (not just errored/unchecked, but completely absent)
    missing_core = _CORE_CHECKS - completed_checks - gap_checks

    # Apply verdict logic
    if should_block:
        return Verdict.NOT_SUITABLE, 1

    if should_undetermined or has_mandatory_gap or gap_checks or missing_core:
        return Verdict.UNDETERMINED, 2

    return Verdict.SUITABLE, 0


__all__ = ["evaluate_verdict"]
