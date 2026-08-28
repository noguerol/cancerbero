from __future__ import annotations

import ast
from pathlib import Path

SOURCE = Path("src/cancerbero")


def imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def test_core_has_no_ml_or_network_framework_imports() -> None:
    forbidden = {
        "torch",
        "transformers",
        "tensorflow",
        "jax",
        "requests",
        "httpx",
        "urllib3",
    }
    imported: set[str] = set()
    for source in SOURCE.rglob("*.py"):
        imported.update(imported_roots(source))
    assert imported.isdisjoint(forbidden)


def test_source_does_not_render_templates_or_map_tensor_files() -> None:
    for source in SOURCE.rglob("*.py"):
        text = source.read_text(encoding="utf-8")
        assert ".render(" not in text, source
        assert "mmap(" not in text, source


def test_no_telemetry_endpoints_or_identifiers() -> None:
    content = "\n".join(path.read_text(encoding="utf-8") for path in SOURCE.rglob("*.py"))
    assert "telemetry_endpoint" not in content.lower()
    assert "analytics_endpoint" not in content.lower()
