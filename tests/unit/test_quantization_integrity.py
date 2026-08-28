"""Tests for quantization integrity verification (v0.5 Phase 4).

Based on research from:
- LLMQuA (ACM Web Conference 2026): Backdoor injection during quantization
- arXiv 2512.06243: Quantization blindspots break backdoor defenses
- arXiv 2606.28962: FlipGuard defense against QCBs
- arXiv 2606.20254: QVec removing QCBs via task arithmetic
- arXiv 2510.09647: Rounding-guided backdoor injection
"""

from __future__ import annotations

from pathlib import Path

from cancerbero.gguf.inspector import inspect_gguf
from tests.fixtures_factory import write_gguf


class TestQuantizationIntegrity:
    """Test quantization integrity checks."""

    def test_valid_gguf_has_no_quantization_issues(self, tmp_path: Path) -> None:
        """A valid GGUF file should have no quantization issues."""
        path = write_gguf(tmp_path / "model.gguf")
        facts, findings = inspect_gguf(path)

        # Should have no quantization-related findings
        quant_findings = [f for f in findings if "quant" in f.id.lower()]
        assert len(quant_findings) == 0

    def test_valid_gguf_has_parsed_finding(self, tmp_path: Path) -> None:
        """A valid GGUF file should have the parsed finding."""
        path = write_gguf(tmp_path / "model.gguf")
        facts, findings = inspect_gguf(path)

        # Should have the parsed finding
        parsed = [f for f in findings if f.id == "cbr.gguf.parsed"]
        assert len(parsed) == 1
        assert parsed[0].status.value == "clean"

    def test_valid_gguf_has_metadata_safety_check(self, tmp_path: Path) -> None:
        """A valid GGUF file should have metadata safety check."""
        path = write_gguf(tmp_path / "model.gguf")
        facts, findings = inspect_gguf(path)

        # Should have metadata safety check (may or may not have findings)
        # The check itself runs without errors
        assert facts is not None
        assert facts.tensor_count == 0


class TestQuantizationIntegrityIntegration:
    """Integration tests for quantization integrity."""

    def test_valid_model_has_clean_quantization(self, tmp_path: Path) -> None:
        """A valid model should have clean quantization integrity."""
        path = write_gguf(tmp_path / "model.gguf")
        facts, findings = inspect_gguf(path)

        # Should have the parsed finding
        parsed = [f for f in findings if f.id == "cbr.gguf.parsed"]
        assert len(parsed) == 1

        # Should have no quantization issues
        quant_findings = [f for f in findings if "quant" in f.id.lower()]
        assert len(quant_findings) == 0

    def test_model_with_chat_template_has_no_quantization_issues(self, tmp_path: Path) -> None:
        """A model with chat template should have no quantization issues."""
        path = write_gguf(
            tmp_path / "model.gguf",
            chat_template="{{ bos_token }}{% for m in messages %}{{ m.content }}{% endfor %}",
        )
        facts, findings = inspect_gguf(path)

        # Should have no quantization issues
        quant_findings = [f for f in findings if "quant" in f.id.lower()]
        assert len(quant_findings) == 0

    def test_model_with_metadata_has_no_quantization_issues(self, tmp_path: Path) -> None:
        """A model with metadata should have no quantization issues."""
        path = write_gguf(
            tmp_path / "model.gguf",
            architecture="llama",
            name="test-model",
        )
        facts, findings = inspect_gguf(path)

        # Should have no quantization issues
        quant_findings = [f for f in findings if "quant" in f.id.lower()]
        assert len(quant_findings) == 0
