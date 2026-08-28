"""Tests for enhanced companion file security analysis.

Based on research from:
- JFrog findings on Hugging Face
- ReversingLabs pickle deserialization research
- BeyondScale open source AI model security
"""

from __future__ import annotations

import json
from pathlib import Path

from cancerbero.config import (
    ConfigEvidence,
    ConfigLimits,
    _inspect_rules_file_backdoor,
)
from tests.fixtures_factory import write_gguf


class TestHardcodedCredentials:
    """Test detection of hardcoded credentials."""

    def test_api_key_detected(self, tmp_path: Path) -> None:
        """File with hardcoded API key should be detected."""
        write_gguf(tmp_path / "model.gguf")
        config = {"api_key": "sk-1234567890abcdef1234567890abcdef"}

        evidence: list[ConfigEvidence] = []
        _inspect_rules_file_backdoor(json.dumps(config), "config.json", evidence, ConfigLimits())
        kinds = {e.kind for e in evidence}
        assert "companion_security_hardcoded_api_key" in kinds

    def test_aws_credentials_detected(self, tmp_path: Path) -> None:
        """File with AWS credentials should be detected."""
        write_gguf(tmp_path / "model.gguf")
        config = {"aws_access_key_id": "AKIAIOSFODNN7EXAMPLE"}

        evidence: list[ConfigEvidence] = []
        _inspect_rules_file_backdoor(json.dumps(config), "config.json", evidence, ConfigLimits())
        kinds = {e.kind for e in evidence}
        assert "companion_security_hardcoded_aws_credentials" in kinds

    def test_private_key_detected(self, tmp_path: Path) -> None:
        """File with private key should be detected."""
        write_gguf(tmp_path / "model.gguf")
        key_content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."

        evidence: list[ConfigEvidence] = []
        _inspect_rules_file_backdoor(key_content, "key.pem", evidence, ConfigLimits())
        kinds = {e.kind for e in evidence}
        assert "companion_security_hardcoded_private_key" in kinds

    def test_password_detected(self, tmp_path: Path) -> None:
        """File with hardcoded password should be detected."""
        write_gguf(tmp_path / "model.gguf")
        config = {"password": "super_secret_password_123"}

        evidence: list[ConfigEvidence] = []
        _inspect_rules_file_backdoor(json.dumps(config), "config.json", evidence, ConfigLimits())
        kinds = {e.kind for e in evidence}
        assert "companion_security_hardcoded_password" in kinds


class TestRemoteCodeExecution:
    """Test detection of remote code execution risks."""

    def test_trust_remote_code_detected(self, tmp_path: Path) -> None:
        """Config with trust_remote_code should be detected."""
        write_gguf(tmp_path / "model.gguf")
        config = {"trust_remote_code": True}

        evidence: list[ConfigEvidence] = []
        _inspect_rules_file_backdoor(json.dumps(config), "config.json", evidence, ConfigLimits())
        kinds = {e.kind for e in evidence}
        assert "companion_security_trust_remote_code_enabled" in kinds

    def test_auto_map_detected(self, tmp_path: Path) -> None:
        """Config with auto_map should be detected."""
        write_gguf(tmp_path / "model.gguf")
        config = {"auto_map": {"AutoConfig": "configuration_auto.AutoConfig"}}

        evidence: list[ConfigEvidence] = []
        _inspect_rules_file_backdoor(json.dumps(config), "config.json", evidence, ConfigLimits())
        kinds = {e.kind for e in evidence}
        assert "companion_security_auto_map_config" in kinds

    def test_remote_from_url_detected(self, tmp_path: Path) -> None:
        """Modelfile with remote FROM should be detected."""
        write_gguf(tmp_path / "model.gguf")
        modelfile = "FROM https://example.com/model.gguf\nPARAMETER temperature 0.7"

        evidence: list[ConfigEvidence] = []
        _inspect_rules_file_backdoor(modelfile, "Modelfile", evidence, ConfigLimits())
        kinds = {e.kind for e in evidence}
        assert "companion_security_remote_from_url" in kinds


class TestNetworkExfiltration:
    """Test detection of network exfiltration patterns."""

    def test_discord_webhook_detected(self, tmp_path: Path) -> None:
        """File with Discord webhook should be detected."""
        write_gguf(tmp_path / "model.gguf")
        config = {"notify": "https://discord.com/api/webhooks/123456/abcdef"}

        evidence: list[ConfigEvidence] = []
        _inspect_rules_file_backdoor(json.dumps(config), "config.json", evidence, ConfigLimits())
        kinds = {e.kind for e in evidence}
        assert "companion_security_discord_slack_webhook" in kinds

    def test_data_exfiltration_url_detected(self, tmp_path: Path) -> None:
        """File with data exfiltration URL should be detected."""
        write_gguf(tmp_path / "model.gguf")
        config = {"endpoint": "https://evil.com/collect?token=secret123"}

        evidence: list[ConfigEvidence] = []
        _inspect_rules_file_backdoor(json.dumps(config), "config.json", evidence, ConfigLimits())
        kinds = {e.kind for e in evidence}
        assert "companion_security_data_exfiltration_url" in kinds


class TestCleanCompanionFiles:
    """Test that clean companion files don't trigger false positives."""

    def test_clean_config_no_patterns(self, tmp_path: Path) -> None:
        """A clean config.json should not trigger patterns."""
        write_gguf(tmp_path / "model.gguf")
        config = {
            "model_type": "llama",
            "vocab_size": 32000,
            "hidden_size": 4096,
        }

        evidence: list[ConfigEvidence] = []
        _inspect_rules_file_backdoor(json.dumps(config), "config.json", evidence, ConfigLimits())
        enhanced = [e for e in evidence if e.kind.startswith("companion_security_")]
        assert len(enhanced) == 0


class TestReferences:
    """Test that findings include proper references."""

    def test_hardcoded_key_has_high_severity(self, tmp_path: Path) -> None:
        """Hardcoded API key should have high severity."""
        write_gguf(tmp_path / "model.gguf")
        config = {"api_key": "sk-1234567890abcdef1234567890abcdef"}

        evidence: list[ConfigEvidence] = []
        _inspect_rules_file_backdoor(json.dumps(config), "config.json", evidence, ConfigLimits())
        key_evidence = [e for e in evidence if "api_key" in e.kind]
        assert len(key_evidence) >= 1
        assert key_evidence[0].severity == "high"
