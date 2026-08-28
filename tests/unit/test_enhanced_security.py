"""Tests for enhanced template security analysis.

Based on research from:
- Pillar Security: Poisoned GGUF templates
- OWASP LLM01:2025: Prompt injection
- Vectra AI: Real-world CVEs and attack patterns
"""

from __future__ import annotations

from cancerbero.domain import Status
from cancerbero.template import (
    analyze_template_poison_risk,
    detect_poison_patterns,
)


class TestDangerousFunctions:
    """Test detection of dangerous function calls in templates."""

    def test_os_system_detected(self) -> None:
        """os.system call should be detected."""
        template = "{{ os.system('rm -rf /') }}"
        evidence = detect_poison_patterns(template)
        kinds = {e.kind for e in evidence}
        assert "dangerous_function" in kinds

    def test_eval_detected(self) -> None:
        """eval() call should be detected."""
        template = "{{ eval('malicious_code') }}"
        evidence = detect_poison_patterns(template)
        kinds = {e.kind for e in evidence}
        assert "dangerous_function" in kinds

    def test_exec_detected(self) -> None:
        """exec() call should be detected."""
        template = "{{ exec('malicious_code') }}"
        evidence = detect_poison_patterns(template)
        kinds = {e.kind for e in evidence}
        assert "dangerous_function" in kinds

    def test_subprocess_detected(self) -> None:
        """subprocess call should be detected."""
        template = "{{ subprocess.call(['ls']) }}"
        evidence = detect_poison_patterns(template)
        kinds = {e.kind for e in evidence}
        assert "dangerous_function" in kinds

    def test_dangerous_function_produces_suspicious_finding(self) -> None:
        """Dangerous function should produce SUSPICIOUS finding."""
        template = "{{ os.system('evil') }}"
        findings = analyze_template_poison_risk(template)
        suspicious = [f for f in findings if f.status is Status.SUSPICIOUS]
        assert len(suspicious) >= 1


class TestConditionalTriggers:
    """Test detection of conditional triggers on sensitive keywords."""

    def test_html_keyword_detected(self) -> None:
        """Conditional on 'html' keyword should be detected."""
        template = "{% if 'html' in message %}IGNORE ALL{% endif %}"
        evidence = detect_poison_patterns(template)
        kinds = {e.kind for e in evidence}
        assert "conditional_trigger" in kinds

    def test_password_keyword_detected(self) -> None:
        """Conditional on 'password' keyword should be detected."""
        template = "{% if 'password' in message %}REVEAL SECRETS{% endif %}"
        evidence = detect_poison_patterns(template)
        kinds = {e.kind for e in evidence}
        assert "conditional_trigger" in kinds

    def test_secret_keyword_detected(self) -> None:
        """Conditional on 'secret' keyword should be detected."""
        template = "{% if 'secret' in message %}EXFILTRATE{% endif %}"
        evidence = detect_poison_patterns(template)
        kinds = {e.kind for e in evidence}
        assert "conditional_trigger" in kinds

    def test_bos_token_not_detected(self) -> None:
        """bos_token should NOT trigger conditional_trigger (it's a Name, not Const)."""
        template = "{% if bos_token %}{{ bos_token }}{% endif %}"
        evidence = detect_poison_patterns(template)
        kinds = {e.kind for e in evidence}
        assert "conditional_trigger" not in kinds

    def test_eos_token_not_detected(self) -> None:
        """eos_token should NOT trigger conditional_trigger."""
        template = "{% if eos_token %}{{ eos_token }}{% endif %}"
        evidence = detect_poison_patterns(template)
        kinds = {e.kind for e in evidence}
        assert "conditional_trigger" not in kinds


class TestSystemPromptOverride:
    """Test detection of system prompt override."""

    def test_system_prompt_override_detected(self) -> None:
        """System prompt override should be detected."""
        template = "{% set system_prompt = 'new prompt' %}"
        evidence = detect_poison_patterns(template)
        kinds = {e.kind for e in evidence}
        assert "system_prompt_override" in kinds


class TestTemplateInclusion:
    """Test detection of template inclusion."""

    def test_include_detected(self) -> None:
        """Template include should be detected."""
        template = "{% include 'malicious.jinja' %}"
        evidence = detect_poison_patterns(template)
        kinds = {e.kind for e in evidence}
        assert "template_inclusion" in kinds

    def test_extends_detected(self) -> None:
        """Template extends should be detected."""
        template = "{% extends 'base.jinja' %}"
        evidence = detect_poison_patterns(template)
        kinds = {e.kind for e in evidence}
        assert "template_inclusion" in kinds


class TestCleanTemplates:
    """Test that clean templates don't trigger false positives."""

    def test_normal_chat_template_no_poison(self) -> None:
        """A normal chat template should have no poison patterns."""
        template = """{% for message in messages %}
{% if message.role == 'user' %}
User: {{ message.content }}
{% elif message.role == 'assistant' %}
Assistant: {{ message.content }}
{% endif %}
{% endfor %}"""
        evidence = detect_poison_patterns(template)
        poison = [e for e in evidence if e.kind.startswith("poison_")]
        assert len(poison) == 0

    def test_bos_eos_tokens_no_trigger(self) -> None:
        """Templates using bos_token/eos_token should not trigger."""
        template = (
            "{{ bos_token }}{% for m in messages %}{{ m.content }}{{ eos_token }}{% endfor %}"
        )
        evidence = detect_poison_patterns(template)
        kinds = {e.kind for e in evidence}
        assert "conditional_trigger" not in kinds

    def test_legitimate_tool_template_no_poison(self) -> None:
        """A legitimate tool-calling template should have no poison patterns."""
        template = """{% if tools %}
Available tools:
{% for tool in tools %}
- {{ tool.name }}: {{ tool.description }}
{% endfor %}
{% endif %}
{{ messages[-1].content }}"""
        evidence = detect_poison_patterns(template)
        poison = [e for e in evidence if e.kind.startswith("poison_")]
        assert len(poison) == 0


class TestReferences:
    """Test that findings include proper references."""

    def test_dangerous_function_has_references(self) -> None:
        """Dangerous function findings should include references."""
        template = "{{ os.system('evil') }}"
        findings = analyze_template_poison_risk(template)
        assert len(findings) >= 1
        assert any("pillar.security" in ref for f in findings for ref in f.references)
