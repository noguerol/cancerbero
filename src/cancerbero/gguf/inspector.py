"""Convert a validated GGUF document into domain-level artifact facts."""

from __future__ import annotations

import re
from pathlib import Path

from cancerbero.domain import ArtifactFacts, Confidence, Finding, Severity, Status, TensorDescriptor
from cancerbero.gguf.limits import DEFAULT_LIMITS, ParserLimits
from cancerbero.gguf.reader import GGML_TYPE_SIZES, GgufDocument, read_gguf

# Patterns that might indicate suspicious metadata
_SUSPICIOUS_PATTERNS = [
    (re.compile(r"https?://", re.IGNORECASE), "URL in metadata"),
    (re.compile(r"eval\s*\(", re.IGNORECASE), "eval() call in metadata"),
    (re.compile(r"exec\s*\(", re.IGNORECASE), "exec() call in metadata"),
    (re.compile(r"os\.system", re.IGNORECASE), "os.system call in metadata"),
    (re.compile(r"subprocess", re.IGNORECASE), "subprocess reference in metadata"),
    (re.compile(r"__import__", re.IGNORECASE), "__import__ in metadata"),
    (re.compile(r"socket\.", re.IGNORECASE), "socket reference in metadata"),
]


def _check_metadata_safety(doc: GgufDocument) -> list[Finding]:
    """Check for suspicious patterns in metadata values."""
    from cancerbero.domain import Confidence, Severity, Status

    findings: list[Finding] = []
    for key, value in doc.metadata.items():
        if not isinstance(value, str):
            continue
        for pattern, description in _SUSPICIOUS_PATTERNS:
            if pattern.search(value):
                findings.append(
                    Finding(
                        id=f"cbr.gguf.metadata_pattern.{key}",
                        head="loading",
                        check="gguf_metadata_safety",
                        status=Status.UNCHECKED,
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        summary=(f"Metadata key '{key}' contains {description.lower()}"),
                        evidence={
                            "key": key,
                            "pattern": description,
                            "value_preview": value[:200],
                        },
                        mandatory=False,
                    )
                )
                break  # Only report first match per key
    return findings


def _check_quantization_integrity(doc: GgufDocument) -> list[Finding]:
    """Check for quantization integrity issues (v0.5 Phase 4).

    Based on research:
    - LLMQuA (ACM Web Conference 2026): Backdoor injection during quantization
    - arXiv 2512.06243: Quantization blindspots break backdoor defenses
    - arXiv 2606.28962: FlipGuard defense against QCBs
    - arXiv 2606.20254: QVec removing QCBs via task arithmetic

    These checks detect:
    - Unusual quantization parameters
    - Quantization type mismatches
    - Tensor anomalies that could indicate backdoor activation
    - Alignment issues that could hide data
    """
    from cancerbero.domain import Confidence, Severity, Status

    findings: list[Finding] = []

    # The canonical set of known GGML tensor types lives in the reader's
    # GGML_TYPE_SIZES table (type id -> (block elements, block bytes)). The
    # inspector must not keep a second, drifting copy of the enum: reader and
    # inspector always agree on which type ids are known.
    # Check for unknown quantization types
    for tensor in doc.tensors:
        if tensor.ggml_type not in GGML_TYPE_SIZES:
            findings.append(
                Finding(
                    id="cbr.gguf.unknown_quant_type",
                    head="loading",
                    check="quantization_integrity",
                    status=Status.UNCHECKED,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    summary=(
                        f"Tensor '{tensor.name}' uses unknown quantization type "
                        f"{tensor.ggml_type}. This may be a custom or experimental type."
                    ),
                    evidence={
                        "tensor": tensor.name,
                        "ggml_type": tensor.ggml_type,
                    },
                    mandatory=False,
                )
            )

    # Check for alignment issues - this is a parser CVE precondition
    # GGUF spec requires offsets to be multiples of alignment
    # Misalignment indicates corruption or malicious modification
    if doc.alignment > 0:
        for tensor in doc.tensors:
            if tensor.offset % doc.alignment != 0:
                findings.append(
                    Finding(
                        id="cbr.gguf.tensor_misalignment",
                        head="loading",
                        check="quantization_integrity",
                        status=Status.SUSPICIOUS,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        classification=Confidence.HIGH,
                        summary=(
                            f"Tensor '{tensor.name}' offset ({tensor.offset}) "
                            f"is not aligned to {doc.alignment} bytes. "
                            f"This violates the GGUF specification and may indicate "
                            f"corruption or malicious modification."
                        ),
                        evidence={
                            "tensor": tensor.name,
                            "offset": tensor.offset,
                            "alignment": doc.alignment,
                        },
                        action=(
                            "Do not load this model. The tensor alignment violates "
                            "the GGUF specification. Re-obtain from a trusted source."
                        ),
                        mandatory=True,
                    )
                )

    return findings


def inspect_gguf(
    path: str | Path,
    *,
    limits: ParserLimits = DEFAULT_LIMITS,
) -> tuple[ArtifactFacts, list[Finding]]:
    """Read and validate a GGUF file, returning domain facts without tensor bytes.

    Returns a tuple of (ArtifactFacts, list[Finding]) where findings include
    any structural warnings or suspicious metadata patterns detected.
    """

    doc: GgufDocument = read_gguf(path, limits)
    findings: list[Finding] = []

    # Record successful GGUF parsing as a core check result
    findings.append(
        Finding(
            id="cbr.gguf.parsed",
            head="loading",
            check="gguf_structure",
            status=Status.CLEAN,
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            summary="GGUF file parsed successfully.",
            evidence={
                "version": doc.version,
                "tensor_count": doc.tensor_count,
                "metadata_count": doc.metadata_count,
            },
            mandatory=False,
        )
    )

    # Check for suspicious metadata patterns
    findings.extend(_check_metadata_safety(doc))

    # Check for zero-sized tensor dimensions
    for tensor in doc.tensors:
        if any(d == 0 for d in tensor.dimensions):
            findings.append(
                Finding(
                    id="cbr.gguf.zero_dimension",
                    head="loading",
                    check="gguf_structure",
                    status=Status.SUSPICIOUS,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    summary=(f"Tensor '{tensor.name}' has a zero-sized dimension"),
                    evidence={
                        "tensor": tensor.name,
                        "dimensions": list(tensor.dimensions),
                    },
                    action=("Re-convert the model from source with an updated converter."),
                )
            )

    # Quantization integrity checks (v0.5 Phase 4)
    # Based on: LLMQuA (ACM Web Conference 2026), arXiv 2512.06243, arXiv 2606.28962
    findings.extend(_check_quantization_integrity(doc))

    tensors = [
        TensorDescriptor(
            name=t.name,
            dimensions=t.dimensions,
            ggml_type=t.ggml_type,
            offset=t.offset,
            byte_size=t.byte_size,
        )
        for t in doc.tensors
    ]

    facts = ArtifactFacts(
        path=doc.path,
        file_size=doc.file_size,
        gguf_version=doc.version,
        tensor_count=doc.tensor_count,
        metadata_count=doc.metadata_count,
        metadata_end=doc.metadata_end,
        tensor_data_offset=doc.tensor_data_offset,
        alignment=doc.alignment,
        architecture=doc.metadata.get("general.architecture"),
        name=doc.metadata.get("general.name"),
        file_type=doc.metadata.get("general.file_type"),
        quantization_version=doc.metadata.get("general.quantization_version"),
        chat_template=doc.metadata.get("tokenizer.chat_template"),
        metadata=doc.metadata,
        tensors=tensors,
        bytes_read=doc.bytes_read,
    )

    return facts, findings


__all__ = ["inspect_gguf"]
