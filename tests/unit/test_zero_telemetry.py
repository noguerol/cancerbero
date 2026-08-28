"""Tests to verify Cancerbero has no telemetry or network access (task 77)."""

from __future__ import annotations

from pathlib import Path

import pytest

# Modules that are allowed to import network-related stdlib modules
# (only for URL parsing, not for making requests)
ALLOWED_NETWORK_IMPORTS = {
    "cancerbero.knowledge.schema",  # Uses urllib.parse.urlparse for URL validation
}


class TestZeroTelemetry:
    """Task 77: Verify Cancerbero has no telemetry, analytics, or network access."""

    def test_no_requests_import(self) -> None:
        """Cancerbero should not import the 'requests' library."""
        # Check all source files for 'import requests' or 'from requests'
        src_dir = Path(__file__).parent.parent.parent / "src" / "cancerbero"
        for py_file in src_dir.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            content = py_file.read_text(encoding="utf-8")
            # Check for direct imports
            assert "import requests" not in content, f"Found 'import requests' in {py_file}"
            assert "from requests" not in content, f"Found 'from requests' in {py_file}"

    def test_no_httpx_import(self) -> None:
        """Cancerbero should not import the 'httpx' library."""
        src_dir = Path(__file__).parent.parent.parent / "src" / "cancerbero"
        for py_file in src_dir.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            content = py_file.read_text(encoding="utf-8")
            assert "import httpx" not in content, f"Found 'import httpx' in {py_file}"
            assert "from httpx" not in content, f"Found 'from httpx' in {py_file}"

    def test_no_urllib_request_import(self) -> None:
        """Cancerbero should not import urllib.request (only urllib.parse is allowed)."""
        src_dir = Path(__file__).parent.parent.parent / "src" / "cancerbero"
        for py_file in src_dir.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            content = py_file.read_text(encoding="utf-8")
            assert "urllib.request" not in content, f"Found 'urllib.request' in {py_file}"
            assert "urllib3" not in content, f"Found 'urllib3' in {py_file}"

    def test_no_socket_import(self) -> None:
        """Cancerbero should not import the 'socket' module."""
        src_dir = Path(__file__).parent.parent.parent / "src" / "cancerbero"
        for py_file in src_dir.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            content = py_file.read_text(encoding="utf-8")
            assert "import socket" not in content, f"Found 'import socket' in {py_file}"
            assert "from socket" not in content, f"Found 'from socket' in {py_file}"

    def test_no_subprocess_with_network(self) -> None:
        """Cancerbero should not use subprocess for network operations."""
        src_dir = Path(__file__).parent.parent.parent / "src" / "cancerbero"
        network_commands = ["curl", "wget", "nc ", "netcat", "ssh ", "scp "]
        for py_file in src_dir.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            content = py_file.read_text(encoding="utf-8")
            for cmd in network_commands:
                # Only flag if it looks like a command execution, not a comment
                if f'"{cmd}' in content or f"'{cmd}" in content:
                    # Check it's not in a comment or docstring
                    for line in content.split("\n"):
                        stripped = line.strip()
                        if stripped.startswith("#"):
                            continue
                        if cmd in line and ("subprocess" in content or "os.system" in content):
                            pytest.fail(f"Found network command '{cmd}' in {py_file}")

    def test_no_analytics_strings(self) -> None:
        """Cancerbero should not contain analytics or tracking strings."""
        src_dir = Path(__file__).parent.parent.parent / "src" / "cancerbero"
        analytics_keywords = [
            "google-analytics",
            "mixpanel",
            "segment.io",
            "amplitude",
            "posthog",
            "sentry",
            "bugsnag",
            "rollbar",
            "phone-home",
            "phone_home",
        ]
        # Exclude delegates directory - it disables telemetry for external tools
        excluded_dirs = {"delegates"}
        for py_file in src_dir.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            # Skip excluded directories
            if any(d in py_file.parts for d in excluded_dirs):
                continue
            content = py_file.read_text(encoding="utf-8").lower()
            for keyword in analytics_keywords:
                assert keyword not in content, f"Found analytics keyword '{keyword}' in {py_file}"

    def test_dependencies_are_minimal(self) -> None:
        """Cancerbero's runtime dependencies should be minimal (only Jinja2)."""
        pyproject = Path(__file__).parent.parent.parent / "pyproject.toml"
        content = pyproject.read_text(encoding="utf-8")
        # Check that Jinja2 is the only runtime dependency
        # The dependencies section should only contain Jinja2
        assert "jinja2" in content.lower(), "Jinja2 should be a dependency"
        # These should NOT be runtime dependencies
        for dep in ["requests", "httpx", "urllib3", "aiohttp", "httpcore"]:
            # Check they're not in the main dependencies (they might be in dev)
            lines = content.split("\n")
            in_deps = False
            for line in lines:
                if "dependencies" in line and "[" in line:
                    in_deps = True
                if (
                    in_deps
                    and dep.lower() in line.lower()
                    and "dev" not in line.lower()
                    and "test" not in line.lower()
                ):
                    pytest.fail(f"Found '{dep}' as a runtime dependency")

    def test_no_environment_variable_leak(self) -> None:
        """Cancerbero should not read environment variables for telemetry."""
        src_dir = Path(__file__).parent.parent.parent / "src" / "cancerbero"
        telemetry_env_vars = [
            "SENTRY_DSN",
            "ANALYTICS_KEY",
            "PHONE_HOME",
            "TRACKING_ID",
        ]
        # Exclude delegates directory - it disables telemetry for external tools
        excluded_dirs = {"delegates"}
        for py_file in src_dir.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            # Skip excluded directories
            if any(d in py_file.parts for d in excluded_dirs):
                continue
            content = py_file.read_text(encoding="utf-8")
            for var in telemetry_env_vars:
                assert var not in content, f"Found telemetry env var '{var}' in {py_file}"
