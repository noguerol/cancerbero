"""Declarative advisory join: artifact predicates × runtime build × advisory rule."""

from __future__ import annotations

from typing import Any

from cancerbero.discovery import LLAMA_CPP_RUNTIME_NAMES
from cancerbero.domain import (
    AdvisoryRule,
    ArtifactFacts,
    Confidence,
    Finding,
    RuntimeFacts,
    Severity,
    Status,
)


def _resolve_field(field: str, artifact: ArtifactFacts | None) -> Any:
    """Resolve a dotted predicate field against artifact facts."""
    parts = field.split(".")
    if parts[0] == "format":
        return "gguf" if artifact is not None else None
    if parts[0] == "architecture":
        return artifact.architecture if artifact is not None else None
    if parts[0] == "name":
        return artifact.name if artifact is not None else None
    if parts[0] == "has_chat_template":
        return artifact.has_chat_template if artifact is not None else None
    if parts[0] == "file_type":
        return artifact.file_type if artifact is not None else None
    if artifact is not None and parts[0] in artifact.metadata:
        return artifact.metadata[parts[0]]
    return None


def _evaluate_predicate(predicate: dict[str, Any], artifact: ArtifactFacts | None) -> bool | None:
    """Evaluate one predicate. Returns True/False or None if the field is absent."""
    operator = predicate["operator"]
    field = predicate["field"]
    value = _resolve_field(field, artifact)
    if operator == "present":
        return value is not None
    if operator == "equals":
        return value == predicate["value"]
    return None


def _parse_semver(version: str) -> tuple[int, ...]:
    """Parse a semver string into a tuple of integers for comparison."""
    # Strip leading 'v' if present
    version = version.lstrip("v")
    # Split on '.' and take numeric parts
    parts = []
    for part in version.split("."):
        # Take only the numeric prefix
        numeric = ""
        for char in part:
            if char.isdigit():
                numeric += char
            else:
                break
        if numeric:
            parts.append(int(numeric))
    return tuple(parts)


def _semver_compare(a: str, b: str) -> int:
    """Compare two semver strings. Returns -1, 0, or 1."""
    pa = _parse_semver(a)
    pb = _parse_semver(b)
    # Pad with zeros to same length
    max_len = max(len(pa), len(pb))
    pa = pa + (0,) * (max_len - len(pa))
    pb = pb + (0,) * (max_len - len(pb))
    if pa < pb:
        return -1
    if pa > pb:
        return 1
    return 0


def _build_in_range(build: int, constraints: dict[str, int | str]) -> bool:
    """Check whether a build number satisfies a range of gt/gte/lt/lte constraints."""
    if "gt" in constraints and build <= constraints["gt"]:
        return False
    if "gte" in constraints and build < constraints["gte"]:
        return False
    if "lt" in constraints and build >= constraints["lt"]:
        return False
    return not ("lte" in constraints and build > constraints["lte"])


def _semver_in_range(version: str, constraints: dict[str, int | str]) -> bool:
    """Check whether a semver version satisfies a range of constraints."""
    if "gt" in constraints and _semver_compare(version, str(constraints["gt"])) <= 0:
        return False
    if "gte" in constraints and _semver_compare(version, str(constraints["gte"])) < 0:
        return False
    if "lt" in constraints and _semver_compare(version, str(constraints["lt"])) >= 0:
        return False
    return not ("lte" in constraints and _semver_compare(version, str(constraints["lte"])) > 0)


def _canonical_component(component: str) -> str:
    """Map a runtime or rule component into the canonical advisory namespace.

    llama.cpp ships many binaries (``llama-cli``, ``llama-server``, ...) that
    all belong to the single ``llama.cpp`` namespace for advisory matching.
    Unknown or third-party components are returned unchanged (casefolded).
    """
    name = component.strip().casefold()
    if name in LLAMA_CPP_RUNTIME_NAMES:
        return "llama.cpp"
    return name


def _runtime_affected(runtime: RuntimeFacts, rule: AdvisoryRule) -> str:
    """Determine whether a runtime build is affected, fixed, or unknown."""
    if rule.version_scheme == "llama_cpp_build":
        if runtime.build is None:
            return "unknown"
        if _build_in_range(runtime.build, rule.affected):
            return "affected"
        if _build_in_range(runtime.build, rule.fixed):
            return "fixed"
    elif rule.version_scheme == "semver":
        if runtime.version is None:
            return "unknown"
        if _semver_in_range(runtime.version, rule.affected):
            return "affected"
        if _semver_in_range(runtime.version, rule.fixed):
            return "fixed"
    return "unknown"


def evaluate_advisory(
    rule: AdvisoryRule,
    artifact: ArtifactFacts | None,
    runtime: RuntimeFacts,
) -> Finding:
    """Evaluate one advisory rule against an artifact and runtime pair."""
    # Check artifact predicates
    for predicate in rule.artifact_predicates:
        result = _evaluate_predicate(predicate, artifact)
        if result is not True:
            return Finding(
                id=f"cbr.join.{rule.id}",
                head="loading",
                check="runtime_advisory_join",
                status=Status.NOT_APPLICABLE,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                summary=f"Advisory {rule.id} does not apply to this artifact.",
                evidence={"advisory": rule.id, "predicate_result": result},
                references=[rule.source],
                mandatory=False,
            )

    # Artifact predicates match; check the runtime component namespace. An
    # advisory declaring a component (e.g. "ollama") never fires for another
    # runtime (e.g. a llama.cpp binary), even when versions happen to overlap.
    if rule.component.strip():
        runtime_component = _canonical_component(runtime.component)
        rule_component = _canonical_component(rule.component)
        if runtime_component != rule_component:
            return Finding(
                id=f"cbr.join.{rule.id}",
                head="loading",
                check="runtime_advisory_join",
                status=Status.NOT_APPLICABLE,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                summary=(f"Advisory {rule.id} targets {rule.component}, not {runtime.component}."),
                evidence={
                    "advisory": rule.id,
                    "rule_component": rule.component,
                    "runtime_component": runtime.component,
                },
                references=[rule.source],
                mandatory=False,
            )

    # Artifact predicates and component match; check runtime
    applicability = _runtime_affected(runtime, rule)
    if applicability == "affected":
        return Finding(
            id=f"cbr.join.{rule.id}",
            head="loading",
            check="runtime_advisory_join",
            status=Status.SUSPICIOUS,
            severity=rule.severity,
            confidence=min(
                rule.confidence,
                runtime.confidence,
                Confidence.HIGH,
                key=lambda c: ["low", "medium", "high"].index(c.value),
            ),
            summary=f"{rule.title}: {rule.explanation}",
            evidence={
                "advisory": rule.id,
                "runtime_build": runtime.build,
                "runtime_version": runtime.version,
                "runtime_detection": runtime.detection_method,
                "applicability": "affected",
            },
            action=rule.action,
            references=[rule.source],
        )
    if applicability == "fixed":
        return Finding(
            id=f"cbr.join.{rule.id}",
            head="loading",
            check="runtime_advisory_join",
            status=Status.VERIFIED,
            severity=Severity.INFO,
            confidence=min(
                rule.confidence,
                runtime.confidence,
                key=lambda c: ["low", "medium", "high"].index(c.value),
            ),
            summary=f"Runtime build is patched for {rule.id}.",
            evidence={
                "advisory": rule.id,
                "runtime_build": runtime.build,
                "applicability": "fixed",
            },
            references=[rule.source],
            mandatory=False,
        )
    # unknown — not mandatory because the runtime may not be detected
    return Finding(
        id=f"cbr.join.{rule.id}",
        head="loading",
        check="runtime_advisory_join",
        status=Status.UNCHECKED,
        severity=Severity.INFO,
        confidence=Confidence.LOW,
        summary=f"Runtime build could not be classified for {rule.id}.",
        evidence={
            "advisory": rule.id,
            "runtime_build": runtime.build,
            "runtime_version": runtime.version,
            "runtime_detection": runtime.detection_method,
            "applicability": "unknown",
        },
        references=[rule.source],
        mandatory=False,
    )


def evaluate_advisories(
    artifact: ArtifactFacts | None,
    runtime: RuntimeFacts,
    rules: tuple[AdvisoryRule, ...],
) -> tuple[Finding, ...]:
    """Evaluate all advisory rules and return findings sorted by id."""
    findings = [evaluate_advisory(rule, artifact, runtime) for rule in rules]
    return tuple(sorted(findings, key=lambda f: f.id))


__all__ = ["evaluate_advisories", "evaluate_advisory"]
