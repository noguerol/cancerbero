"""Tests for runtime configuration security analysis.

Based on research from:
- CVE-2026-21869: Negative parameter triggers OOB write
- TheHackerWire: llama.cpp Server RCE
"""

from __future__ import annotations

from cancerbero.runtime_config import (
    analyze_runtime_config,
    analyze_runtime_flags,
)


class TestRuntimeConfigAnalysis:
    """Test runtime configuration analysis."""

    def test_clean_config_has_no_findings(self) -> None:
        """A clean configuration should have no findings."""
        config = """
# llama.cpp server configuration
model = ./model.gguf
port = 8080
host = 127.0.0.1
"""
        result = analyze_runtime_config(config, "config.conf")
        assert len(result.findings) == 0

    def test_bind_all_interfaces_detected(self) -> None:
        """Binding to all interfaces should be detected."""
        config = """
# Server configuration
--host 0.0.0.0
--port 8080
"""
        result = analyze_runtime_config(config, "config.conf")
        findings = [f for f in result.findings if "bind_all_interfaces" in f.id]
        assert len(findings) >= 1
        assert findings[0].status.value == "suspicious"

    def test_api_key_in_args_detected(self) -> None:
        """API key in command line should be detected."""
        config = """
# Server configuration
--api-key sk-1234567890abcdef
"""
        result = analyze_runtime_config(config, "config.conf")
        findings = [f for f in result.findings if "api_key_in_args" in f.id]
        assert len(findings) >= 1
        assert findings[0].status.value == "suspicious"

    def test_network_access_flag_set(self) -> None:
        """Network access flag should be set when binding to interfaces."""
        config = """
# Server configuration
--host 0.0.0.0
--port 8080
"""
        result = analyze_runtime_config(config, "config.conf")
        assert result.has_network_access is True


class TestRuntimeFlagsAnalysis:
    """Test runtime command-line flags analysis."""

    def test_clean_flags_have_no_findings(self) -> None:
        """Clean flags should have no findings."""
        flags = ["--model", "./model.gguf", "--host", "127.0.0.1"]
        result = analyze_runtime_flags(flags)
        assert len(result.findings) == 0

    def test_bind_all_interfaces_detected_in_flags(self) -> None:
        """Binding to all interfaces should be detected in flags."""
        flags = ["--host", "0.0.0.0", "--port", "8080"]
        result = analyze_runtime_flags(flags)
        findings = [f for f in result.findings if "bind_all_interfaces" in f.id]
        assert len(findings) >= 1

    def test_api_key_detected_in_flags(self) -> None:
        """API key should be detected in flags."""
        flags = ["--api-key", "sk-1234567890abcdef"]
        result = analyze_runtime_flags(flags)
        findings = [f for f in result.findings if "api_key_in_args" in f.id]
        assert len(findings) >= 1
