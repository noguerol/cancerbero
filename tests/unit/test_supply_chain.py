"""Tests for supply chain verification.

Based on research from:
- Hive Security: Hugging Face supply chain attacks
- ReversingLabs: nullifAI technique
- BeyondScale: Open source AI model security
"""

from __future__ import annotations

from pathlib import Path

from cancerbero.supply_chain import (
    analyze_supply_chain,
)


class TestSupplyChainAnalysis:
    """Test supply chain verification."""

    def test_clean_model_has_no_findings(self, tmp_path: Path) -> None:
        """A clean model should have no supply chain findings."""
        model_path = tmp_path / "my-model-Q4_K_M.gguf"
        model_path.write_bytes(b"\x00" * 100)

        result = analyze_supply_chain(
            model_name="my-model",
            model_path=model_path,
        )
        assert len(result.findings) == 0

    def test_suspicious_file_type_detected(self, tmp_path: Path) -> None:
        """A model with suspicious file extension should be detected."""
        model_path = tmp_path / "model.exe"
        model_path.write_bytes(b"\x00" * 100)

        result = analyze_supply_chain(
            model_name="model",
            model_path=model_path,
        )
        findings = [f for f in result.findings if "suspicious_file_type" in f.id]
        assert len(findings) >= 1

    def test_suspicious_repo_url_detected(self, tmp_path: Path) -> None:
        """A model with suspicious repo URL should be detected."""
        model_path = tmp_path / "model.gguf"
        model_path.write_bytes(b"\x00" * 100)

        result = analyze_supply_chain(
            model_name="model",
            model_path=model_path,
            metadata={"general.repo_url": "https://malicious-models.com/model"},
        )
        findings = [f for f in result.findings if "suspicious_repo" in f.id]
        assert len(findings) >= 1

    def test_clean_repo_url_not_flagged(self, tmp_path: Path) -> None:
        """A model with clean repo URL should not be flagged."""
        model_path = tmp_path / "model.gguf"
        model_path.write_bytes(b"\x00" * 100)

        result = analyze_supply_chain(
            model_name="model",
            model_path=model_path,
            metadata={"general.repo_url": "https://huggingface.co/org/model"},
        )
        findings = [f for f in result.findings if "suspicious_repo" in f.id]
        assert len(findings) == 0

    def test_no_metadata_no_findings(self, tmp_path: Path) -> None:
        """A model without metadata should have no supply chain findings."""
        model_path = tmp_path / "model.gguf"
        model_path.write_bytes(b"\x00" * 100)

        result = analyze_supply_chain(
            model_name=None,
            model_path=model_path,
        )
        # Should have no findings (no model name to check)
        assert len(result.findings) == 0
