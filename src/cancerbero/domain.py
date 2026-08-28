"""Stable domain contracts used by inspectors, policy, and reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Status(str, Enum):
    VERIFIED = "verified"
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    UNCHECKED = "unchecked"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Verdict(str, Enum):
    """Suitability for the checks actually performed, never a safety seal."""

    SUITABLE = "suitable"
    NOT_SUITABLE = "not_suitable"
    UNDETERMINED = "undetermined"


class TargetKind(str, Enum):
    GGUF = "gguf"
    LLAMA_CPP_RUNTIME = "llama_cpp_runtime"
    DIRECTORY = "directory"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class Target:
    path: Path
    kind: TargetKind
    detection_method: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "kind": self.kind.value,
            "detection_method": self.detection_method,
        }


@dataclass(slots=True)
class TensorDescriptor:
    name: str
    dimensions: tuple[int, ...]
    ggml_type: int
    offset: int
    byte_size: int | None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["dimensions"] = list(self.dimensions)
        return data


@dataclass(slots=True)
class ArtifactFacts:
    path: Path
    file_size: int
    gguf_version: int
    tensor_count: int
    metadata_count: int
    metadata_end: int
    tensor_data_offset: int
    alignment: int
    architecture: str | None = None
    name: str | None = None
    file_type: int | None = None
    quantization_version: int | None = None
    chat_template: str | None = None
    sha256: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    tensors: list[TensorDescriptor] = field(default_factory=list)
    bytes_read: int = 0

    @property
    def has_chat_template(self) -> bool:
        return self.chat_template is not None

    def to_dict(self, *, include_template: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "path": str(self.path),
            "format": "gguf",
            "file_size": self.file_size,
            "gguf_version": self.gguf_version,
            "tensor_count": self.tensor_count,
            "metadata_count": self.metadata_count,
            "metadata_end": self.metadata_end,
            "tensor_data_offset": self.tensor_data_offset,
            "alignment": self.alignment,
            "architecture": self.architecture,
            "name": self.name,
            "file_type": self.file_type,
            "quantization_version": self.quantization_version,
            "has_chat_template": self.has_chat_template,
            "sha256": self.sha256,
            "bytes_read": self.bytes_read,
            "tensors": [tensor.to_dict() for tensor in self.tensors],
        }
        if include_template:
            data["chat_template"] = self.chat_template
        return data


@dataclass(slots=True)
class RuntimeFacts:
    path: Path
    component: str
    version: str | None = None
    build: int | None = None
    commit: str | None = None
    detection_method: str = "none"
    confidence: Confidence = Confidence.LOW
    executable_format: str | None = None
    writable_by_group: bool = False
    writable_by_others: bool = False
    executed: bool = False
    flags: tuple[str, ...] = ()

    @property
    def is_identified(self) -> bool:
        return self.version is not None or self.build is not None or self.commit is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "component": self.component,
            "version": self.version,
            "build": self.build,
            "commit": self.commit,
            "detection_method": self.detection_method,
            "confidence": self.confidence.value,
            "executable_format": self.executable_format,
            "writable_by_group": self.writable_by_group,
            "writable_by_others": self.writable_by_others,
            "executed": self.executed,
            "flags": list(self.flags),
        }


@dataclass(frozen=True, slots=True)
class AdvisoryRule:
    id: str
    title: str
    source: str
    component: str
    version_scheme: str
    affected: dict[str, Any]
    fixed: dict[str, Any]
    artifact_predicates: tuple[dict[str, Any], ...]
    severity: Severity
    confidence: Confidence
    explanation: str
    action: str
    published: str
    reviewed: str


@dataclass(slots=True)
class Finding:
    id: str
    head: str
    check: str
    status: Status
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.HIGH
    classification: Confidence = Confidence.HIGH  # Confidence in malice classification
    summary: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    action: str | None = None
    references: list[str] = field(default_factory=list)
    mandatory: bool = True

    def __post_init__(self) -> None:
        if self.status is not Status.SUSPICIOUS and self.severity not in {
            Severity.INFO,
            Severity.LOW,
        }:
            raise ValueError("Only suspicious findings may have medium or higher severity")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "head": self.head,
            "check": self.check,
            "status": self.status.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "summary": self.summary,
            "evidence": self.evidence,
            "action": self.action,
            "references": sorted(self.references),
            "mandatory": self.mandatory,
            "classification": self.classification.value,
        }


@dataclass(slots=True)
class BundleInfo:
    schema_version: str
    bundle_version: str
    published_at: str
    expires_at: str
    digest_sha256: str
    source: str
    integrity: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(slots=True)
class AuditReport:
    schema_version: str
    cancerbero_version: str
    command: list[str]
    targets: list[Target]
    artifacts: list[ArtifactFacts]
    runtimes: list[RuntimeFacts]
    findings: list[Finding]
    bundle: BundleInfo | None
    verdict: Verdict
    exit_code: int
    deterministic_options: dict[str, Any] = field(default_factory=dict)
    observations: dict[str, Any] = field(default_factory=dict)
    hardening_recommendations: list[Any] = field(default_factory=list)

    def deterministic_dict(self) -> dict[str, Any]:
        """Return reproducible content, excluding wall-clock time and durations."""
        return {
            "schema_version": self.schema_version,
            "cancerbero_version": self.cancerbero_version,
            "command": self.command,
            "targets": [target.to_dict() for target in self.targets],
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "runtimes": [runtime.to_dict() for runtime in self.runtimes],
            "findings": [
                finding.to_dict() for finding in sorted(self.findings, key=lambda item: item.id)
            ],
            "bundle": self.bundle.to_dict() if self.bundle else None,
            "verdict": self.verdict.value,
            "exit_code": self.exit_code,
            "options": self.deterministic_options,
            "coverage": coverage_summary(self.findings),
            "limitations": [
                "Cancerbero does not prove that an artifact is safe or free of backdoors.",
                "The default check does not execute the model, templates, or discovered runtimes.",
            ],
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.deterministic_dict()
        if self.observations:
            data["observations"] = self.observations
        return data


def coverage_summary(findings: list[Finding]) -> dict[str, int]:
    counts = {status.value: 0 for status in Status}
    for finding in findings:
        counts[finding.status.value] += 1
    counts["total"] = len(findings)
    return counts
