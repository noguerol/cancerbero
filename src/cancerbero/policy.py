"""Verdict and exit-code policy for Cancerbero findings."""

from __future__ import annotations

from cancerbero.domain import Confidence, Finding, Severity, Status, Verdict

# Core checks that must produce positive evidence for a SUITABLE verdict.
# If any core check is missing (unchecked/error), the verdict is UNDETERMINED.
# This prevents the "SUITABLE on no evidence" problem.
#
# ``runtime_advisory_join`` is only REQUIRED when a runtime is in scope.
# When no runtime was provided we still attempt a no-runtime join and emit
# an UNCHECKED finding; the policy then degrades this check to optional
# rather than failing the verdict. This avoids the
# "downloaded an unverified GGUF, no runtime, can't say anything" trap that
# previously produced UNDETERMINED indistinguishable from a real failure.
_CORE_CHECKS: frozenset[str] = frozenset(
    {
        "gguf_structure",  # GGUF parsed successfully
        "chat_template_static",  # Template analyzed (present or absent)
    }
)
_RUNTIME_CORE_CHECK = "runtime_advisory_join"


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


def evaluate_verdict(
    findings: tuple[Finding, ...],
    *,
    runtime_in_scope: bool = True,
) -> tuple[Verdict, int]:
    """Determine the verdict and exit code from a set of findings.

    Policy:
    - Severity × Classification matrix determines blocking
    - Core checks must have positive evidence for SUITABLE
    - Missing core checks → UNDETERMINED, unless ``runtime_in_scope`` is
      False and the only missing core check is ``runtime_advisory_join``;
      in that case we return ``CLEAN`` because we ran the checks we could.

    Core checks are: ``gguf_structure``, ``chat_template_static``,
    ``runtime_advisory_join`` (only when a runtime is in scope).
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
            and finding.check != _RUNTIME_CORE_CHECK
        ):
            has_mandatory_gap = True

        # Track statuses per check for core check evaluation
        effective_core_checks = _CORE_CHECKS | (
            {_RUNTIME_CORE_CHECK} if runtime_in_scope else set()
        )
        if finding.check in effective_core_checks:
            if finding.check not in check_statuses:
                check_statuses[finding.check] = []
            check_statuses[finding.check].append(finding.status)

    # For core checks: only count as gap if ALL findings for that check are unchecked/error
    # If at least one finding is verified/clean/not_applicable, the check has positive evidence
    effective_core_checks = _CORE_CHECKS | ({_RUNTIME_CORE_CHECK} if runtime_in_scope else set())
    for check in effective_core_checks:
        if check in check_statuses:
            statuses = check_statuses[check]
            has_positive = any(
                s in {Status.VERIFIED, Status.CLEAN, Status.NOT_APPLICABLE} for s in statuses
            )
            if not has_positive:
                gap_checks.add(check)

    # Check for missing core checks (not just errored/unchecked, but completely absent)
    missing_core = effective_core_checks - completed_checks - gap_checks

    # Apply verdict logic
    if should_block:
        return Verdict.NOT_SUITABLE, 1

    non_runtime_gaps = {g for g in (gap_checks | missing_core) if g != _RUNTIME_CORE_CHECK}

    if should_undetermined or has_mandatory_gap or gap_checks or missing_core:
        # If the ONLY missing/gapped core check is the runtime join AND no
        # runtime was supplied, downgrade to CLEAN (we ran the checks we
        # could and found nothing suspicious).
        if not should_undetermined and not has_mandatory_gap and not non_runtime_gaps:
            return Verdict.CLEAN, 0
        return Verdict.UNDETERMINED, 2

    # No missing core checks and nothing blocking. SUITABLE requires full
    # coverage (every core check produced positive evidence). When the
    # runtime was out of scope we did not run ``runtime_advisory_join``,
    # so we cannot claim full coverage; emit CLEAN instead. CLEAN means
    # "no suspicious findings on the checks we performed" — distinct from
    # UNDETERMINED ("a check ran and we don't know the answer") and from
    # SUITABLE ("every core check produced positive evidence").
    if not runtime_in_scope:
        return Verdict.CLEAN, 0

    return Verdict.SUITABLE, 0


__all__ = ["evaluate_verdict"]
