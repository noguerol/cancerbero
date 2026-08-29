"""Tests for quantization integrity verification (regression for G2).

The previous ``cbr.gguf.unknown_quant_type``, ``cbr.gguf.tensor_misalignment``
and ``cbr.gguf.zero_dimension`` findings could never be emitted from a
real GGUF file because the GGUF reader (``cancerbero.gguf.reader``) rejects
every condition that those findings targeted with a typed exception
(``GgufTypeError``, ``GgufRangeError``, ``GgufValidationError``) before
``inspect_gguf`` ever sees the document. These tests now assert that
contract end-to-end: a structurally invalid GGUF fails at parse time, not
at inspection time, so the operator sees a clear error rather than an
unreachable "suspicious" finding.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cancerbero.gguf.inspector import inspect_gguf
from cancerbero.gguf.reader import (
    GgufRangeError,
    GgufTypeError,
    GgufValidationError,
)
from tests.fixtures_factory import build_gguf_v2, write_gguf


class TestQuantizationIntegrity:
    """End-to-end checks that the reader, not the inspector, enforces
    tensor-type / alignment / dimension invariants."""

    def test_valid_gguf_has_no_quantization_issues(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "model.gguf")
        facts, findings = inspect_gguf(path)
        # No quantization-related findings on a valid GGUF.
        quant_findings = [f for f in findings if "quant" in f.id.lower()]
        assert quant_findings == []

    def test_valid_gguf_has_parsed_finding(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "model.gguf")
        facts, findings = inspect_gguf(path)
        parsed = [f for f in findings if f.id == "cbr.gguf.parsed"]
        assert len(parsed) == 1
        assert parsed[0].status.value == "clean"

    def test_unknown_tensor_type_rejected_by_reader(self, tmp_path: Path) -> None:
        """Type id 4 is a GGML hole. The reader raises before the inspector
        could ever see the tensor, so ``cbr.gguf.unknown_quant_type`` is
        unreachable on parsed GGUF files."""
        data = build_gguf_v2(tensors=[("t", (32, 1), 4, 0)])
        path = tmp_path / "type-4.gguf"
        path.write_bytes(data + b"\x00" * 18)
        with pytest.raises(GgufTypeError):
            inspect_gguf(path)

    def test_misaligned_tensor_rejected_by_reader(self, tmp_path: Path) -> None:
        """A tensor offset that is not a multiple of ``general.alignment``
        is rejected at parse time so the inspector never sees it."""
        data = build_gguf_v2(tensors=[("t", (32, 1), 1, 7)])  # 7 % 32 != 0
        path = tmp_path / "misaligned.gguf"
        path.write_bytes(data + b"\x00" * 2)
        with pytest.raises(GgufRangeError):
            inspect_gguf(path)

    def test_zero_dimensional_tensor_rejected_by_reader(self, tmp_path: Path) -> None:
        """A tensor with a zero dimension is rejected by the reader, so
        ``cbr.gguf.zero_dimension`` is unreachable on parsed GGUF files."""
        data = build_gguf_v2(tensors=[("t", (0, 1), 1, 0)])
        path = tmp_path / "zero.gguf"
        path.write_bytes(data + b"\x00" * 2)
        with pytest.raises(GgufValidationError, match="zero-sized"):
            inspect_gguf(path)


class TestQuantizationIntegrityIntegration:
    """Integration tests for the post-G2 behaviour."""

    def test_valid_model_has_clean_quantization(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "model.gguf")
        facts, findings = inspect_gguf(path)
        parsed = [f for f in findings if f.id == "cbr.gguf.parsed"]
        assert len(parsed) == 1
        quant_findings = [f for f in findings if "quant" in f.id.lower()]
        assert quant_findings == []

    def test_model_with_chat_template_has_no_quantization_issues(self, tmp_path: Path) -> None:
        path = write_gguf(
            tmp_path / "model.gguf",
            chat_template="{{ bos_token }}{% for m in messages %}{{ m.content }}{% endfor %}",
        )
        facts, findings = inspect_gguf(path)
        quant_findings = [f for f in findings if "quant" in f.id.lower()]
        assert quant_findings == []

    def test_model_with_metadata_has_no_quantization_issues(self, tmp_path: Path) -> None:
        path = write_gguf(
            tmp_path / "model.gguf",
            architecture="llama",
            name="test-model",
        )
        facts, findings = inspect_gguf(path)
        quant_findings = [f for f in findings if "quant" in f.id.lower()]
        assert quant_findings == []
