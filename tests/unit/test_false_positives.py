"""Regression suite: official chat templates must not produce blocking findings.

This encodes the invariant that the tool must satisfy before it can be released:

    A stock, unmodified chat template from a mainstream model family must
    never yield a SUSPICIOUS finding, and must be able to reach SUITABLE
    when paired with a valid runtime.

Grow this corpus over time. Every family you add is a family you can no
longer break silently.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from cancerbero.audit import CheckOptions, run_check
from cancerbero.domain import Status

# Add tests directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))
from gguf_builder import build
from real_templates import TEMPLATES


def _findings_for(tmp_path: Path, name: str, template: str):
    """Run the full inspection pipeline over a synthetic GGUF."""
    path = tmp_path / f"{name}.gguf"
    build(str(path), name=name, tmpl=template)
    options = CheckOptions(targets=(path,))
    return run_check(options, command=["test"])


@pytest.mark.parametrize("family", sorted(TEMPLATES))
def test_official_template_produces_no_blocking_finding(tmp_path, family):
    """No stock template may yield a SUSPICIOUS finding."""
    report = _findings_for(tmp_path, family, TEMPLATES[family])
    suspicious = [f for f in report.findings if f.status is Status.SUSPICIOUS]
    assert not suspicious, f"{family}: false positives -> " + ", ".join(
        f"{f.id} ({f.severity.name})" for f in suspicious
    )


def test_template_analysis_survives_deep_nesting(tmp_path):
    """A deeply nested template must be reported, never crash the process."""
    from cancerbero.template import analyze_chat_template

    hostile = "{% if a %}" * 1500 + "x" + "{% endif %}" * 1500
    try:
        analysis = analyze_chat_template(hostile)
        # Should return an error analysis, not crash
        assert analysis.parsed is False or analysis.limit_exceeded is True
    except RecursionError:
        pytest.fail("analyze_chat_template raised an uncaught RecursionError")
    except Exception as exc:
        # A bounded, typed template error is the acceptable outcome.
        assert "template" in type(exc).__name__.lower() or "limit" in str(exc).lower()


def test_bos_token_does_not_trigger_conditional_trigger(tmp_path):
    """bos_token/eos_token must not trigger conditional_trigger."""
    template = "{{ bos_token }}{% for m in messages %}{{ m.content }}{{ eos_token }}{% endfor %}"
    report = _findings_for(tmp_path, "bos_test", template)
    suspicious = [f for f in report.findings if f.status is Status.SUSPICIOUS]
    assert not suspicious, "bos_token triggered false positive: " + ", ".join(
        f.id for f in suspicious
    )


def test_role_redefinition_not_flagged(tmp_path):
    """Templates that mention system/user/assistant should not be flagged."""
    template = """{% for message in messages %}
{% if message.role == 'system' %}System: {{ message.content }}
{% elif message.role == 'user' %}User: {{ message.content }}
{% elif message.role == 'assistant' %}Assistant: {{ message.content }}
{% endif %}
{% endfor %}"""
    report = _findings_for(tmp_path, "role_test", template)
    suspicious = [f for f in report.findings if f.status is Status.SUSPICIOUS]
    assert not suspicious, "Role mentions triggered false positive: " + ", ".join(
        f.id for f in suspicious
    )
