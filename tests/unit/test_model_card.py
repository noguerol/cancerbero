"""Tests for model card and documentation analysis.

Based on research from:
- Hive Security - Hugging Face supply chain attacks
- ReversingLabs - nullifAI technique
- BeyondScale - Open source AI model security
"""

from __future__ import annotations

from pathlib import Path

from cancerbero.config import (
    ConfigEvidence,
    ConfigLimits,
    analyze_model_card,
)
from tests.fixtures_factory import write_gguf


class TestMaliciousPatterns:
    """Test detection of known malicious patterns in documentation."""

    def test_credential_harvest_detected(self, tmp_path: Path) -> None:
        """Documentation with credential harvesting should be detected."""
        write_gguf(tmp_path / "model.gguf")
        readme = "# Model\n\nPlease send your API key to activate."

        evidence: list[ConfigEvidence] = []
        analyze_model_card(readme, "README.md", evidence, ConfigLimits())
        kinds = {e.kind for e in evidence}
        assert "model_card_credential_harvest_doc" in kinds

    def test_shortened_url_detected(self, tmp_path: Path) -> None:
        """Documentation with shortened URLs should be detected."""
        write_gguf(tmp_path / "model.gguf")
        readme = "# Model\n\nDownload from https://bit.ly/evil-model"

        evidence: list[ConfigEvidence] = []
        analyze_model_card(readme, "README.md", evidence, ConfigLimits())
        kinds = {e.kind for e in evidence}
        assert "model_card_suspicious_shortened_url" in kinds


class TestCleanModelCards:
    """Test that clean model cards don't trigger false positives."""

    def test_clean_readme_no_patterns(self, tmp_path: Path) -> None:
        """A clean README should not trigger patterns."""
        write_gguf(tmp_path / "model.gguf")
        readme = """# My Model

This is a fine-tuned Llama model for chat.

## License

Apache 2.0

## Training Data

Trained on OpenAssistant conversations.

## Usage

```python
from transformers import AutoModelForCausalLM
model = AutoModelForCausalLM.from_pretrained("my-org/my-model")
```
"""

        evidence: list[ConfigEvidence] = []
        analyze_model_card(readme, "README.md", evidence, ConfigLimits())
        # Should have no high-risk patterns
        high_risk = [e for e in evidence if e.severity == "high"]
        assert len(high_risk) == 0


class TestReferences:
    """Test that findings include proper references."""

    def test_credential_harvest_has_high_severity(self, tmp_path: Path) -> None:
        """Credential harvest should have high severity."""
        write_gguf(tmp_path / "model.gguf")
        readme = "# Model\n\nPlease send your API key to activate."

        evidence: list[ConfigEvidence] = []
        analyze_model_card(readme, "README.md", evidence, ConfigLimits())
        harvest = [e for e in evidence if "credential" in e.kind]
        assert len(harvest) >= 1
        assert harvest[0].severity == "high"
