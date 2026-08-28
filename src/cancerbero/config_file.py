"""Configuration file support for Cancerbero."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ConfigFileError(ValueError):
    """Raised when a configuration file cannot be parsed or loaded."""


def _looks_like_yaml(text: str) -> bool:
    """Heuristic: does non-JSON text resemble YAML enough to need PyYAML?"""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Document markers, list items, and key: value mappings are YAML
        # idioms that JSON cannot express without a parser.
        if stripped in {"---", "..."} or stripped.startswith("- "):
            return True
        if ":" in stripped and "://" not in stripped:
            return True
    return False


def _load_json_fallback(config_path: Path) -> dict[str, Any]:
    """Parse a config file as JSON when PyYAML is unavailable.

    Valid JSON is a YAML subset, so the fallback keeps JSON-only configs
    working without the optional dependency. Files that look like YAML
    instead raise :class:`ConfigFileError` rather than silently applying
    defaults.
    """

    try:
        with open(config_path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        try:
            raw = config_path.read_text(encoding="utf-8")
        except OSError:
            return {}
        if raw.strip() and _looks_like_yaml(raw):
            raise ConfigFileError(f"{config_path}: Install PyYAML or convert to JSON") from exc
        return {}
    return data if isinstance(data, dict) else {}


@dataclass(slots=True)
class CancerberoConfig:
    """Configuration loaded from cancerbero.yaml or defaults."""

    # Runtime options
    runtime: Path | None = None
    runtime_version: str | None = None
    allow_runtime_exec: bool = False

    # Hash options
    full_hash: bool = False
    expected_sha256: str | None = None

    # Output options
    format: str = "terminal"  # terminal, json, markdown, sarif
    json_path: str | None = None
    include_observations: bool = False
    verbose: bool = False
    no_color: bool = False

    # Template options
    template_ref: str | None = None

    # Explain mode
    explain: str | None = None

    # Batch mode
    summary_only: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize config to dict for JSON output."""
        return {
            "runtime": str(self.runtime) if self.runtime else None,
            "runtime_version": self.runtime_version,
            "allow_runtime_exec": self.allow_runtime_exec,
            "full_hash": self.full_hash,
            "expected_sha256": self.expected_sha256,
            "format": self.format,
            "verbose": self.verbose,
            "template_ref": self.template_ref,
            "explain": self.explain,
            "summary_only": self.summary_only,
        }


def find_config_file() -> Path | None:
    """Find the configuration file in standard locations."""
    # 1. Current directory
    cwd_config = Path("cancerbero.yaml")
    if cwd_config.exists():
        return cwd_config

    # 2. User config directory
    home_config = Path.home() / ".cancerbero" / "config.yaml"
    if home_config.exists():
        return home_config

    # 3. Environment variable
    env_config = os.environ.get("CANCERBERO_CONFIG")
    if env_config:
        path = Path(env_config)
        if path.exists():
            return path

    return None


def load_config(config_path: Path | None = None) -> CancerberoConfig:
    """Load configuration from file or return defaults."""
    config = CancerberoConfig()

    if config_path is None:
        config_path = find_config_file()

    if config_path is None or not config_path.exists():
        return config

    data: Any = {}
    try:
        import yaml

        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except ImportError:
        # PyYAML is not installed; JSON is a YAML subset, so fall back to it.
        data = _load_json_fallback(config_path)
    except yaml.YAMLError as exc:
        raise ConfigFileError(f"{config_path}: invalid YAML configuration ({exc})") from exc
    except OSError:
        return config
    if not isinstance(data, dict):
        data = {}

    # Apply config values
    if "runtime" in data and data["runtime"]:
        config.runtime = Path(data["runtime"])
    if "runtime_version" in data:
        config.runtime_version = data["runtime_version"]
    if "allow_runtime_exec" in data:
        config.allow_runtime_exec = bool(data["allow_runtime_exec"])
    if "full_hash" in data:
        config.full_hash = bool(data["full_hash"])
    if "expected_sha256" in data:
        config.expected_sha256 = data["expected_sha256"]
    if "format" in data:
        config.format = data["format"]
    if "verbose" in data:
        config.verbose = bool(data["verbose"])
    if "no_color" in data:
        config.no_color = bool(data["no_color"])
    if "template_ref" in data:
        config.template_ref = data["template_ref"]
    if "explain" in data:
        config.explain = data["explain"]
    if "summary_only" in data:
        config.summary_only = bool(data["summary_only"])

    return config


def merge_config(
    config: CancerberoConfig,
    *,
    runtime: Path | None = None,
    runtime_version: str | None = None,
    allow_runtime_exec: bool | None = None,
    full_hash: bool | None = None,
    expected_sha256: str | None = None,
    format: str | None = None,
    json_path: str | None = None,
    include_observations: bool | None = None,
    verbose: bool | None = None,
    no_color: bool | None = None,
    template_ref: str | None = None,
    explain: str | None = None,
    summary_only: bool | None = None,
) -> CancerberoConfig:
    """Merge CLI arguments with config file values."""
    if runtime is not None:
        config.runtime = runtime
    if runtime_version is not None:
        config.runtime_version = runtime_version
    if allow_runtime_exec is not None:
        config.allow_runtime_exec = allow_runtime_exec
    if full_hash is not None:
        config.full_hash = full_hash
    if expected_sha256 is not None:
        config.expected_sha256 = expected_sha256
    if format is not None:
        config.format = format
    if json_path is not None:
        config.json_path = json_path
    if include_observations is not None:
        config.include_observations = include_observations
    if verbose is not None:
        config.verbose = verbose
    if no_color is not None:
        config.no_color = no_color
    if template_ref is not None:
        config.template_ref = template_ref
    if explain is not None:
        config.explain = explain
    if summary_only is not None:
        config.summary_only = summary_only
    return config


__all__ = [
    "CancerberoConfig",
    "ConfigFileError",
    "find_config_file",
    "load_config",
    "merge_config",
]
