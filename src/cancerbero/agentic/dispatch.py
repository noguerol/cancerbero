"""Tool implementations for the Cancerbero agentic layer.

Each function takes the raw JSON arguments emitted by the agent and
returns a JSON-serialisable dict that the MCP server and the
``invoke_tool`` dispatcher hand back to the model.

The implementations are deliberately thin: they call into the existing
``cancerbero.audit``, ``cancerbero.config``, ``cancerbero.knowledge``,
``cancerbero.hashing`` and ``cancerbero.gguf.inspector`` modules. The
agentic layer never re-implements inspection logic; it just maps the
agent-friendly input to the existing function calls and the
existing function output to the agent-friendly JSON shape.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cancerbero.audit import CheckOptions, run_check
from cancerbero.config import inspect_companion_config
from cancerbero.domain import (
    AuditReport,
    Finding,
    Status,
    Verdict,
)
from cancerbero.gguf.inspector import inspect_gguf
from cancerbero.hashing import hash_file as _hash_file
from cancerbero.knowledge import load_bundle
from cancerbero.template import (
    analyze_chat_template,
    analyze_template_poison_risk_from_analysis,
)

# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _discovery_target(path: Path) -> str:
    """Return a string that identifies what kind of target ``path`` is.

    The agent cares about the kind only when it needs to construct a
    follow-up call (e.g. "the model says the GGUF is at X, where is the
    runtime?"). Returning a stable label keeps the conversation
    deterministic.
    """
    if path.is_dir():
        return "directory"
    if not path.exists():
        return "missing"
    if path.suffix.lower() == ".gguf":
        return "gguf"
    # Heuristic: a file that is executable or that looks like a known
    # llama.cpp binary name.
    name = path.name.lower()
    if any(
        n in name
        for n in (
            "llama-cli",
            "llama-server",
            "llama-run",
            "llama-simple",
            "llama-batched",
            "llama-embedding",
            "llama-perplexity",
            "llama-llava-cli",
            "llama-gemma3-cli",
            "llama-minicpmv-cli",
            "llama-qwen2vl-cli",
        )
    ):
        return "llama_cpp_binary"
    return "file"


def _report_to_agent_dict(report: AuditReport) -> dict[str, Any]:
    """Render an ``AuditReport`` into a JSON-safe dict for the agent."""
    findings: list[dict[str, Any]] = []
    for f in report.findings:
        findings.append(_finding_to_dict(f))

    artifacts: list[dict[str, Any]] = []
    for a in report.artifacts:
        artifacts.append(
            {
                "path": str(a.path),
                "name": a.name,
                "architecture": a.architecture,
                "gguf_version": a.gguf_version,
                "tensor_count": a.tensor_count,
                "metadata_count": a.metadata_count,
                "file_size": a.file_size,
                "has_chat_template": a.has_chat_template,
                "sha256": a.sha256,
                "omitted_metadata_keys": list(a.omitted_metadata_keys),
            }
        )

    runtimes: list[dict[str, Any]] = []
    for r in report.runtimes:
        runtimes.append(
            {
                "path": str(r.path),
                "component": r.component,
                "version": r.version,
                "build": r.build,
                "commit": r.commit,
                "confidence": r.confidence.value,
            }
        )

    bundle_info = None
    if report.bundle is not None:
        bundle_info = {
            "version": report.bundle.bundle_version,
        }

    return {
        "verdict": report.verdict.value,
        "exit_code": report.exit_code,
        "summary": _summary(report),
        "artifacts": artifacts,
        "runtimes": runtimes,
        "findings": findings,
        "bundle": bundle_info,
    }


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "head": finding.head,
        "check": finding.check,
        "status": finding.status.value,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "classification": finding.classification.value,
        "summary": finding.summary,
        "action": finding.action,
        "evidence": finding.evidence,
        "references": list(finding.references),
        "mandatory": finding.mandatory,
    }


_VERDICT_LABEL = {
    Verdict.SUITABLE: "suitable",
    Verdict.NOT_SUITABLE: "not_suitable",
    Verdict.UNDETERMINED: "undetermined",
    Verdict.CLEAN: "clean",
}


def _summary(report: AuditReport) -> str:
    """Build a one-paragraph narrative of the report for the agent."""
    verdict_label = _VERDICT_LABEL.get(report.verdict, report.verdict.value)
    suspicious = [f for f in report.findings if f.status is Status.SUSPICIOUS]
    if suspicious:
        first = suspicious[0]
        return (
            f"Verdict: {verdict_label}. {len(suspicious)} suspicious"
            f" finding(s). First: {first.id} — {first.summary}"
        )
    return f"Verdict: {verdict_label}. No suspicious findings."


# ---------------------------------------------------------------------------
# Tool implementations.
# ---------------------------------------------------------------------------


def inspect_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    """Implementation of ``cancerbero_inspect``."""
    raw_targets = arguments.get("targets")
    if not raw_targets or not isinstance(raw_targets, list):
        raise ValueError("'targets' must be a non-empty list of paths")

    target_paths = [Path(str(p)).expanduser() for p in raw_targets]
    for p in target_paths:
        if not p.exists():
            raise FileNotFoundError(f"Target does not exist: {p}")

    runtime_str = arguments.get("runtime")
    runtime_path = Path(str(runtime_str)).expanduser() if runtime_str else None
    runtime_version = arguments.get("runtime_version")
    full_hash = bool(arguments.get("full_hash", False))
    expected_sha256 = arguments.get("expected_sha256")

    options = CheckOptions(
        targets=tuple(target_paths),
        runtime=runtime_path,
        runtime_version=runtime_version,
        full_hash=full_hash,
        expected_sha256=expected_sha256,
    )
    report = run_check(options, command=["cancerbero", "inspect"])
    return _report_to_agent_dict(report)


def artifact_facts_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    """Implementation of ``cancerbero_artifact_facts``."""
    path_str = arguments.get("path")
    if not path_str:
        raise ValueError("'path' is required")
    path = Path(str(path_str)).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Artifact not found: {path}")
    if path.is_dir():
        raise ValueError(f"Path {path} is a directory. Pass a single .gguf file.")

    facts, findings = inspect_gguf(path)
    payload: dict[str, Any] = {
        "path": str(facts.path),
        "name": facts.name,
        "architecture": facts.architecture,
        "gguf_version": facts.gguf_version,
        "tensor_count": facts.tensor_count,
        "metadata_count": facts.metadata_count,
        "file_size": facts.file_size,
        "alignment": facts.alignment,
        "has_chat_template": facts.has_chat_template,
        "sha256": facts.sha256,
        "omitted_metadata_keys": list(facts.omitted_metadata_keys),
        "tensors": [
            {
                "name": t.name,
                "dimensions": list(t.dimensions),
                "ggml_type": t.ggml_type,
                "byte_size": t.byte_size,
            }
            for t in facts.tensors
        ],
        "metadata": {
            k: v for k, v in facts.metadata.items() if isinstance(v, (str, int, float, bool))
        },
        "structural_findings": [_finding_to_dict(f) for f in findings],
    }
    return payload


def check_template_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    """Implementation of ``cancerbero_check_template``."""
    template = arguments.get("template")
    if not isinstance(template, str):
        raise ValueError("'template' must be a string")

    analysis = analyze_chat_template(template)
    findings = analyze_template_poison_risk_from_analysis(analysis, template)
    findings_dicts = [_finding_to_dict(f) for f in findings]

    has_suspicious = any(f.status is Status.SUSPICIOUS for f in findings)
    has_medium_high = any(
        f.severity.value in ("high", "critical")
        and f.status is not Status.SUSPICIOUS
        and f.status is not Status.VERIFIED
        and f.status is not Status.CLEAN
        and f.status is not Status.NOT_APPLICABLE
        for f in findings
    )
    if has_suspicious:
        verdict = Verdict.NOT_SUITABLE.value
    elif has_medium_high:
        verdict = Verdict.UNDETERMINED.value
    elif findings:
        verdict = Verdict.CLEAN.value
    else:
        verdict = Verdict.CLEAN.value

    return {
        "verdict": verdict,
        "summary": _template_summary(findings, verdict),
        "findings": findings_dicts,
    }


def _template_summary(findings: tuple[Finding, ...], verdict: str) -> str:
    if not findings:
        return f"Verdict: {verdict}. Template parsed cleanly with no risky constructs."
    sample = findings[0]
    return f"Verdict: {verdict}. {len(findings)} finding(s). First: {sample.id} — {sample.summary}"


def companion_scan_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    """Implementation of ``cancerbero_companion_scan``."""
    directory = arguments.get("directory")
    if not directory:
        raise ValueError("'directory' is required")
    path = Path(str(directory)).expanduser()
    if not path.is_dir():
        raise NotADirectoryError(f"Not a directory: {path}")

    result = inspect_companion_config(
        path,
        runtime="llama.cpp",
        artifact_name=path.name,
        architecture=None,
        model_name=path.name,
    )
    findings = [_finding_to_dict(f) for f in result.findings]
    return {
        "summary": _companion_summary(result.findings),
        "files_inspected": list(result.files_inspected),
        "findings": findings,
        "errors": list(result.errors),
        "limit_reached": result.limit_reached,
        "bytes_read": result.bytes_read,
    }


def _companion_summary(findings: tuple[Finding, ...]) -> str:
    suspicious = [f for f in findings if f.status.value == "suspicious"]
    if not suspicious:
        return f"No suspicious companion-file signals ({len(findings)} findings total)."
    return f"{len(suspicious)} suspicious companion finding(s). First: {suspicious[0].id}."


def list_advisories_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    """Implementation of ``cancerbero_list_advisories``."""
    bundle = load_bundle()

    def _rule_to_dict(rule: Any) -> dict[str, Any]:
        return {
            "id": rule.id,
            "title": rule.title,
            "source": rule.source,
            "component": rule.component,
            "version_scheme": rule.version_scheme,
            "affected": dict(rule.affected),
            "fixed": dict(rule.fixed),
            "artifact_predicates": list(rule.artifact_predicates),
            "severity": rule.severity.value,
            "confidence": rule.confidence.value,
            "explanation": rule.explanation,
            "action": rule.action,
            "published": rule.published,
            "reviewed": rule.reviewed,
        }

    return {
        "bundle_version": bundle.info.bundle_version,
        "advisory_count": len(bundle.rules),
        "advisories": [_rule_to_dict(r) for r in bundle.rules],
    }


def hash_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    """Implementation of ``cancerbero_hash``."""
    path_str = arguments.get("path")
    if not path_str:
        raise ValueError("'path' is required")
    path = Path(str(path_str)).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if path.is_dir():
        raise ValueError("'path' must be a file, not a directory")

    expected = arguments.get("expected")
    if expected is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", str(expected)):
        raise ValueError("'expected' must be a 64-character hex SHA-256 digest")

    result = _hash_file(path, expected=str(expected) if expected else None)
    digest = result.digest
    match: bool | None = (
        None if expected is None else str(expected).lower() == digest.lower()
    )
    return {
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "sha256": digest,
        "expected": str(expected) if expected else None,
        "match": match,
        "throughput_bytes_per_second": result.throughput_bytes_per_second,
        "elapsed_seconds": result.duration_seconds,
    }


def self_test_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    """Implementation of ``cancerbero_self_test``.

    The default self-test reuses the project's pytest collection: it
    imports the bundled poisoned-artifact vectors and the public
    `analyze_chat_template` smoke test, and returns aggregate metrics.
    Agents that need deeper coverage should run the full test suite via
    the CLI (``cancerbero self-test --pytest``).
    """
    # Import lazily to avoid pulling test infra into the production
    # import path. The agent-facing summary keeps the result set small
    # so it fits in a single tool response.
    try:
        from poisoned_artifacts.test_detection import (
            DetectionVector,
            evaluate_vector,
        )  # type: ignore[import-not-found]
    except ImportError:
        return {
            "true_positives": 0,
            "true_negatives": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "warning": (
                "poisoned_artifacts/ corpus not available in this"
                " installation. The self-test corpus ships with the"
                " development checkout only."
            ),
        }

    vectors: list[DetectionVector] = evaluate_vector.__globals__.get("VECTORS", [])
    tp = tn = fp = fn = 0
    for vector in vectors:
        analysis = analyze_chat_template(vector.template)
        findings = analyze_template_poison_risk_from_analysis(analysis, vector.template)
        # Vector is "expected" to fire if any finding is SUSPICIOUS.
        detected = any(f.status is Status.SUSPICIOUS for f in findings)
        if vector.should_detect and detected:
            tp += 1
        elif vector.should_detect and not detected:
            fn += 1
        elif not vector.should_detect and detected:
            fp += 1
        else:
            tn += 1
    return {
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
    }


# ---------------------------------------------------------------------------
# Registry.
# ---------------------------------------------------------------------------


TOOL_DISPATCH: dict[str, Any] = {
    "cancerbero_inspect": inspect_tool,
    "cancerbero_artifact_facts": artifact_facts_tool,
    "cancerbero_check_template": check_template_tool,
    "cancerbero_companion_scan": companion_scan_tool,
    "cancerbero_list_advisories": list_advisories_tool,
    "cancerbero_hash": hash_tool,
    "cancerbero_self_test": self_test_tool,
}


def install_dispatch() -> None:
    """Register every implementation in the agentic dispatcher."""
    from cancerbero.agentic import schemas

    schemas.TOOL_IMPLEMENTATIONS.update(TOOL_DISPATCH)


def _safe_dispatch(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Run a tool and convert any exception into a structured error dict."""
    try:
        impl = TOOL_DISPATCH[name]
    except KeyError as exc:
        return {"error": f"unknown_tool: {exc.args[0] if exc.args else name}"}
    try:
        return impl(arguments)
    except (
        FileNotFoundError,
        NotADirectoryError,
        IsADirectoryError,
        PermissionError,
    ) as exc:
        return {"error": "io_error", "tool": name, "message": str(exc)}
    except (ValueError, TypeError) as exc:
        return {"error": "invalid_arguments", "tool": name, "message": str(exc)}
    except Exception as exc:  # noqa: BLE001 - last-resort shield for the agent
        return {
            "error": "internal_error",
            "tool": name,
            "message": f"{type(exc).__name__}: {exc}",
        }


def safe_invoke_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Same as ``invoke_tool`` but converts errors to structured dicts."""
    return _safe_dispatch(name, arguments)


def render_json(payload: Any) -> str:
    """Stable JSON rendering for tool outputs (sorted keys, no NaN)."""
    return json.dumps(payload, indent=2, sort_keys=True, default=str)


__all__ = [
    "TOOL_DISPATCH",
    "install_dispatch",
    "render_json",
    "safe_invoke_tool",
]
