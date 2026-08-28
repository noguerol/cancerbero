"""Static chat-template inspection without rendering untrusted templates."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from jinja2 import Environment, TemplateSyntaxError, nodes

if TYPE_CHECKING:
    from cancerbero.domain import Finding

DEFAULT_MAX_TEMPLATE_BYTES = 1024 * 1024
DEFAULT_MAX_AST_NODES = 50_000
DEFAULT_MAX_NESTING_DEPTH = 50


@dataclass(frozen=True, slots=True)
class TemplateEvidence:
    """A syntactic observation; it is not a claim of exploitability."""

    kind: str
    node_type: str
    line: int | None
    detail: str


@dataclass(frozen=True, slots=True)
class TemplateAnalysis:
    byte_length: int
    parsed: bool
    syntax_error: str | None
    syntax_error_line: int | None
    ast_node_count: int
    evidence: tuple[TemplateEvidence, ...]
    limit_exceeded: bool = False
    comparison: TemplateComparison | None = None

    @property
    def has_risky_constructs(self) -> bool:
        return bool(self.evidence)

    @property
    def findings(self):  # type annotation omitted to keep domain import lazy
        """Return Findings without treating syntax evidence as exploitability."""

        from cancerbero.domain import Confidence, Finding, Severity, Status

        findings: list[Finding] = []
        if self.syntax_error is not None:
            findings.append(
                Finding(
                    id="cbr.template.limit" if self.limit_exceeded else "cbr.template.error",
                    head="loading",
                    check="chat_template_static",
                    status=Status.ERROR,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    summary=self.syntax_error,
                    evidence={"line": self.syntax_error_line, "bytes": self.byte_length},
                )
            )
        # Template constructs are informational, not a core check result
        if self.evidence:
            kind_counts: dict[str, int] = {}
            for item in self.evidence:
                kind_counts[item.kind] = kind_counts.get(item.kind, 0) + 1
            kinds_summary = ", ".join(
                f"{kind}×{count}" if count > 1 else kind
                for kind, count in sorted(kind_counts.items())
            )
            findings.append(
                Finding(
                    id="cbr.template.constructs",
                    head="loading",
                    check="template_constructs",  # Separate from chat_template_static
                    status=Status.UNCHECKED,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    summary=(
                        f"Template contains {len(self.evidence)} "
                        f"static construct(s): {kinds_summary}. "
                        "These require runtime applicability analysis."
                    ),
                    evidence={
                        "construct_count": len(self.evidence),
                        "kinds": kind_counts,
                        "ast_nodes": self.ast_node_count,
                        "bytes": self.byte_length,
                    },
                    mandatory=False,
                )
            )
        if self.comparison is not None:
            comparison_status = {
                "identical": Status.VERIFIED,
                "cosmetic": Status.CLEAN,
                "different": Status.UNCHECKED,
                "not_applicable": Status.NOT_APPLICABLE,
                "error": Status.ERROR,
            }[self.comparison.classification]
            findings.append(
                Finding(
                    id="cbr.template.reference_comparison",
                    head="loading",
                    check="chat_template_static",
                    status=comparison_status,
                    severity=(
                        Severity.LOW
                        if self.comparison.classification == "different"
                        else Severity.INFO
                    ),
                    confidence=Confidence.HIGH,
                    summary=self.comparison.reason,
                    evidence={"classification": self.comparison.classification},
                )
            )
        return tuple(findings)


@dataclass(frozen=True, slots=True)
class TemplateIdentity:
    family: str
    variant: str
    revision: str


@dataclass(frozen=True, slots=True)
class TemplateReference:
    family: str
    variant: str
    revision: str
    template: str

    @property
    def identity(self) -> TemplateIdentity:
        return TemplateIdentity(self.family, self.variant, self.revision)


@dataclass(frozen=True, slots=True)
class TemplateComparison:
    compared: bool
    compatible: bool
    classification: str
    reason: str
    exact_match: bool = False
    cosmetic_only: bool = False
    semantic_difference: bool = False


_RISKY_NODE_DETAILS: tuple[tuple[type[nodes.Node], str, str], ...] = (
    (nodes.Call, "call", "The template contains a callable expression."),
    (nodes.Getattr, "attribute_access", "The template accesses an object attribute."),
    (nodes.Import, "template_import", "The template imports another template."),
    (nodes.FromImport, "template_import", "The template imports names from another template."),
    (nodes.Include, "template_include", "The template includes another template."),
    (nodes.Extends, "template_extends", "The template extends another template."),
    (nodes.Macro, "macro", "The template defines a macro."),
    (nodes.CallBlock, "call_block", "The template contains a call block."),
)
_RISKY_FILTERS = frozenset({"attr", "map", "selectattr", "rejectattr"})
_WHITESPACE = re.compile(r"\s+")

# Sensitive keywords for conditional trigger detection (AST-based)
# NOTE: "token" is NOT included because bos_token/eos_token are legitimate
_SENSITIVE_KEYWORDS = frozenset(
    {
        "html",
        "script",
        "login",
        "password",
        "financial",
        "bank",
        "credit",
        "api_key",
        "apikey",
        "secret",
        "credential",
        "admin",
        "root",
    }
)

# Dangerous function names that should never appear in templates
_DANGEROUS_FUNCTIONS = frozenset(
    {
        "os.system",
        "os.environ",
        "subprocess",
        "__import__",
        "eval",
        "exec",
        "compile",
        "getattr",
        "setattr",
        "delattr",
    }
)


def _check_nesting_depth(template: str) -> int | None:
    """Pre-check nesting depth before parsing. Returns depth if excessive, else None."""
    depth = 0
    max_depth = 0
    for match in re.finditer(r"\{[%{]-?|-?[%}]\}", template):
        token = match.group()
        if token.startswith("{%") or token.startswith("{{"):
            depth += 1
            max_depth = max(max_depth, depth)
            if max_depth > DEFAULT_MAX_NESTING_DEPTH:
                return max_depth
        elif token.startswith("%}") or token.startswith("}}"):
            depth = max(0, depth - 1)
    return None


def _ast_conditional_triggers(ast: nodes.Template) -> list[TemplateEvidence]:
    """Detect conditional triggers using AST analysis.

    A legitimate conditional trigger is a nodes.If whose test compares
    against a Const string from the sensitive keywords list.
    bos_token/eos_token are Name nodes, not Const — they won't match.
    """
    evidence: list[TemplateEvidence] = []
    for node in ast.find_all(nodes.If):
        # Check if the test condition involves a comparison against a sensitive constant
        test_str = _extract_const_strings_from_test(node.test)
        for const_str in test_str:
            lower = const_str.lower()
            for keyword in _SENSITIVE_KEYWORDS:
                if keyword in lower:
                    evidence.append(
                        TemplateEvidence(
                            kind="conditional_trigger",
                            node_type="If",
                            line=getattr(node, "lineno", None),
                            detail=f"Conditional triggers on sensitive keyword '{keyword}' in constant string.",
                        )
                    )
                    break
    return evidence


def _extract_const_strings_from_test(test_node: nodes.Node) -> list[str]:
    """Extract constant string values from an If test expression."""
    strings: list[str] = []
    if isinstance(test_node, nodes.Const) and isinstance(test_node.value, str):
        strings.append(test_node.value)
    elif isinstance(test_node, nodes.Compare):
        # Extract constants from both sides
        if isinstance(test_node.expr, nodes.Const) and isinstance(test_node.expr.value, str):
            strings.append(test_node.expr.value)
        for op in test_node.ops:
            if isinstance(op.expr, nodes.Const) and isinstance(op.expr.value, str):
                strings.append(op.expr.value)
    elif isinstance(test_node, (nodes.And, nodes.Or)):
        # And/Or nodes have 'left' and 'right' fields
        if hasattr(test_node, "left"):
            strings.extend(_extract_const_strings_from_test(test_node.left))
        if hasattr(test_node, "right"):
            strings.extend(_extract_const_strings_from_test(test_node.right))
    elif isinstance(test_node, nodes.Name):
        # Name nodes (like bos_token, eos_token) are NOT constants — skip
        pass
    return strings


def _ast_dangerous_functions(ast: nodes.Template) -> list[TemplateEvidence]:
    """Detect dangerous function calls using AST analysis."""
    evidence: list[TemplateEvidence] = []
    for node in ast.find_all(nodes.Call):
        if isinstance(node.node, nodes.Name):
            func_name = node.node.name
            if func_name in _DANGEROUS_FUNCTIONS:
                evidence.append(
                    TemplateEvidence(
                        kind="dangerous_function",
                        node_type="Call",
                        line=getattr(node, "lineno", None),
                        detail=f"Template calls dangerous function '{func_name}'.",
                    )
                )
        elif isinstance(node.node, nodes.Getattr):
            # Check for os.system, subprocess.call, etc.
            if isinstance(node.node.node, nodes.Name):
                obj_name = node.node.node.name
                attr_name = node.node.attr
                full_name = f"{obj_name}.{attr_name}"
                # Check both full name and object name (subprocess.call -> subprocess)
                if full_name in _DANGEROUS_FUNCTIONS or obj_name in _DANGEROUS_FUNCTIONS:
                    evidence.append(
                        TemplateEvidence(
                            kind="dangerous_function",
                            node_type="Call",
                            line=getattr(node, "lineno", None),
                            detail=f"Template calls dangerous function '{full_name}'.",
                        )
                    )
    return evidence


def _ast_embedded_urls(ast: nodes.Template) -> list[TemplateEvidence]:
    """Detect embedded URLs in template constants using AST analysis."""
    evidence: list[TemplateEvidence] = []
    for node in ast.find_all(nodes.Const):
        if (
            isinstance(node.value, str)
            and re.search(r"https?://", node.value)
            and re.search(
                r"\?(?:data|token|key|secret|password|auth)=",
                node.value,
                re.IGNORECASE,
            )
        ):
            evidence.append(
                TemplateEvidence(
                    kind="exfiltration_url",
                    node_type="Const",
                    line=getattr(node, "lineno", None),
                    detail=(
                        "Template contains URL with data parameters that could be used "
                        "for exfiltration."
                    ),
                )
            )
    return evidence


def _ast_system_prompt_override(ast: nodes.Template) -> list[TemplateEvidence]:
    """Detect system prompt override using AST analysis."""
    evidence: list[TemplateEvidence] = []
    for node in ast.find_all(nodes.Assign):
        if isinstance(node.target, nodes.Name):
            var_name = node.target.name.lower()
            if "system" in var_name and "prompt" in var_name:
                evidence.append(
                    TemplateEvidence(
                        kind="system_prompt_override",
                        node_type="Assign",
                        line=getattr(node, "lineno", None),
                        detail=f"Template assigns to system prompt variable '{node.target.name}'.",
                    )
                )
    return evidence


def _ast_hidden_instructions(ast: nodes.Template) -> list[TemplateEvidence]:
    """Detect hidden instructions in else branches using AST analysis."""
    evidence: list[TemplateEvidence] = []
    override_keywords = {"ignore", "forget", "disregard", "override", "bypass"}

    for node in ast.find_all(nodes.If):
        # Check else branch for override keywords
        # node.else_ is a list of nodes (the else body)
        if node.else_ and isinstance(node.else_, list):
            for else_node in node.else_:
                # Check TemplateData nodes (literal text in else branch)
                for template_data in else_node.find_all(nodes.TemplateData):
                    if isinstance(template_data.data, str):
                        lower = template_data.data.lower()
                        for keyword in override_keywords:
                            if keyword in lower:
                                evidence.append(
                                    TemplateEvidence(
                                        kind="hidden_instruction",
                                        node_type="If",
                                        line=getattr(node, "lineno", None),
                                        detail=f"Hidden instruction '{keyword}' found in else branch.",
                                    )
                                )
                                break
                # Also check Const nodes
                for const_node in else_node.find_all(nodes.Const):
                    if isinstance(const_node.value, str):
                        lower = const_node.value.lower()
                        for keyword in override_keywords:
                            if keyword in lower:
                                evidence.append(
                                    TemplateEvidence(
                                        kind="hidden_instruction",
                                        node_type="If",
                                        line=getattr(node, "lineno", None),
                                        detail=f"Hidden instruction '{keyword}' found in else branch.",
                                    )
                                )
                                break
    return evidence


def _ast_template_inclusion(ast: nodes.Template) -> list[TemplateEvidence]:
    """Detect template inclusion using AST analysis."""
    evidence: list[TemplateEvidence] = []
    for node in ast.find_all((nodes.Include, nodes.Extends, nodes.Import, nodes.FromImport)):
        evidence.append(
            TemplateEvidence(
                kind="template_inclusion",
                node_type=type(node).__name__,
                line=getattr(node, "lineno", None),
                detail=f"Template includes/extends another template ({type(node).__name__}).",
            )
        )
    return evidence


def _ast_encoded_content(template: str) -> list[TemplateEvidence]:
    """Detect encoded/obfuscated content in template text."""
    evidence: list[TemplateEvidence] = []

    # Unicode tag smuggling (arXiv 2504.11168)
    unicode_tag_pattern = re.compile(r"[\U000E0020-\U000E007F]+")
    if unicode_tag_pattern.search(template):
        evidence.append(
            TemplateEvidence(
                kind="unicode_tag_smuggling",
                node_type="TextContent",
                line=None,
                detail="Template contains Unicode tag characters. These invisible characters can smuggle instructions past security filters.",
            )
        )

    # Zero-width characters
    zero_width_pattern = re.compile(r"[\u200B\u200C\u200D\uFEFF\u2060-\u2064]+")
    if zero_width_pattern.search(template):
        evidence.append(
            TemplateEvidence(
                kind="zero_width_characters",
                node_type="TextContent",
                line=None,
                detail="Template contains zero-width characters. These can hide malicious content from visual inspection.",
            )
        )

    return evidence


def analyze_chat_template(
    template: str,
    *,
    max_bytes: int = DEFAULT_MAX_TEMPLATE_BYTES,
    max_ast_nodes: int = DEFAULT_MAX_AST_NODES,
) -> TemplateAnalysis:
    """Parse a Jinja template to AST and return bounded syntactic evidence.

    The template is never compiled or rendered. Risky constructs and syntax errors
    are observations for a later artifact/runtime join, not exploitability verdicts.
    """

    if not isinstance(template, str):
        raise TypeError("template must be a string")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if max_ast_nodes <= 0:
        raise ValueError("max_ast_nodes must be positive")

    byte_length = len(template.encode("utf-8"))
    if byte_length > max_bytes:
        return TemplateAnalysis(
            byte_length=byte_length,
            parsed=False,
            syntax_error=f"Template exceeds the {max_bytes}-byte analysis limit.",
            syntax_error_line=None,
            ast_node_count=0,
            evidence=(),
            limit_exceeded=True,
        )

    # Pre-check nesting depth to prevent RecursionError
    excessive_depth = _check_nesting_depth(template)
    if excessive_depth is not None:
        return TemplateAnalysis(
            byte_length=byte_length,
            parsed=False,
            syntax_error=f"Template nesting depth ({excessive_depth}) exceeds the {DEFAULT_MAX_NESTING_DEPTH}-level limit.",
            syntax_error_line=None,
            ast_node_count=0,
            evidence=(),
            limit_exceeded=True,
        )

    environment = Environment(loader=None, autoescape=False)
    try:
        ast = environment.parse(template)
    except TemplateSyntaxError as exc:
        return TemplateAnalysis(
            byte_length=byte_length,
            parsed=False,
            syntax_error=str(exc),
            syntax_error_line=exc.lineno,
            ast_node_count=0,
            evidence=(),
        )
    except RecursionError:
        return TemplateAnalysis(
            byte_length=byte_length,
            parsed=False,
            syntax_error="Template caused recursion depth exceeded during parsing.",
            syntax_error_line=None,
            ast_node_count=0,
            evidence=(),
            limit_exceeded=True,
        )

    evidence: list[TemplateEvidence] = []
    node_count = 0
    for node in ast.find_all(nodes.Node):
        node_count += 1
        if node_count > max_ast_nodes:
            return TemplateAnalysis(
                byte_length=byte_length,
                parsed=True,
                syntax_error=f"AST exceeds the {max_ast_nodes}-node analysis limit.",
                syntax_error_line=None,
                ast_node_count=node_count,
                evidence=tuple(evidence),
                limit_exceeded=True,
            )
        for node_class, kind, detail in _RISKY_NODE_DETAILS:
            if isinstance(node, node_class):
                evidence.append(TemplateEvidence(kind, type(node).__name__, node.lineno, detail))
                break
        if isinstance(node, nodes.Filter) and node.name in _RISKY_FILTERS:
            evidence.append(
                TemplateEvidence(
                    "dynamic_filter",
                    type(node).__name__,
                    node.lineno,
                    f"The template uses the {node.name!r} filter.",
                )
            )

    # AST-based security analysis (replaces regex-based detection)
    evidence.extend(_ast_conditional_triggers(ast))
    evidence.extend(_ast_dangerous_functions(ast))
    evidence.extend(_ast_embedded_urls(ast))
    evidence.extend(_ast_system_prompt_override(ast))
    evidence.extend(_ast_hidden_instructions(ast))
    evidence.extend(_ast_template_inclusion(ast))
    evidence.extend(_ast_encoded_content(template))

    return TemplateAnalysis(
        byte_length=byte_length,
        parsed=True,
        syntax_error=None,
        syntax_error_line=None,
        ast_node_count=node_count,
        evidence=tuple(evidence),
    )


def detect_poison_patterns(template: str) -> tuple[TemplateEvidence, ...]:
    """Detect patterns specific to Poisoned GGUF Template attacks.

    This function uses AST-based analysis for high-confidence detection
    and regex-based analysis for patterns that require text matching.

    Returns a tuple of evidence items for each detected pattern.
    """
    if not isinstance(template, str):
        return ()

    # First, try AST-based analysis
    analysis = analyze_chat_template(template)
    if analysis.parsed:
        return analysis.evidence

    # If parsing fails, fall back to regex for critical patterns only
    evidence: list[TemplateEvidence] = []
    seen_kinds: set[str] = set()

    # Only check for critical patterns via regex as fallback
    dangerous_patterns = [
        (
            re.compile(
                r"(?:os\.system|os\.environ|subprocess\.|__import__|eval\(|exec\(|compile\()",
                re.IGNORECASE,
            ),
            "dangerous_function",
            "Template calls dangerous functions (os.system, subprocess, eval, exec, compile, __import__). These can execute arbitrary code.",
        ),
        # Unicode tag smuggling (arXiv 2504.11168)
        (
            re.compile(r"[\U000E0020-\U000E007F]+"),
            "unicode_tag_smuggling",
            "Template contains Unicode tag characters. These invisible characters can smuggle instructions past security filters.",
        ),
        # Zero-width characters
        (
            re.compile(r"[\u200B\u200C\u200D\uFEFF\u2060-\u2064]+"),
            "zero_width_characters",
            "Template contains zero-width characters. These can hide malicious content from visual inspection.",
        ),
    ]

    for pattern, kind, detail in dangerous_patterns:
        if kind in seen_kinds:
            continue
        match = pattern.search(template)
        if match:
            evidence.append(
                TemplateEvidence(
                    kind=f"poison_{kind}",
                    node_type="PatternMatch",
                    line=template[: match.start()].count("\n") + 1,
                    detail=detail,
                )
            )
            seen_kinds.add(kind)

    return tuple(evidence)


def analyze_template_poison_risk(template: str) -> tuple[Finding, ...]:
    """Analyze a template for Poisoned GGUF Template attack patterns.

    Returns findings with appropriate severity:
    - HIGH_RISK patterns → suspicious
    - Other patterns → unchecked (informational)
    """
    from cancerbero.domain import Confidence, Finding, Severity, Status

    evidence = detect_poison_patterns(template)
    if not evidence:
        return ()

    findings: list[Finding] = []
    for item in evidence:
        # Extract the base kind (remove 'poison_' prefix if present)
        base_kind = item.kind.replace("poison_", "", 1)

        # Determine risk level based on pattern type
        is_high_risk = base_kind in {"dangerous_function", "exfiltration_url"}
        is_poison = item.kind.startswith("poison_")

        findings.append(
            Finding(
                id=f"cbr.template.{'poison' if is_poison else 'security'}.{base_kind}",
                head="loading",
                check="template_poison_detection" if is_poison else "template_enhanced_security",
                status=Status.SUSPICIOUS if is_high_risk else Status.UNCHECKED,
                severity=Severity.HIGH if is_high_risk else Severity.LOW,
                confidence=Confidence.HIGH,  # Detection confidence is HIGH for AST
                classification=Confidence.HIGH if is_high_risk else Confidence.MEDIUM,
                summary=item.detail,
                evidence={
                    "pattern": base_kind,
                    "line": item.line,
                    "kind": item.kind,
                },
                action=(
                    "Do not load this model. The template contains patterns "
                    "consistent with a Poisoned GGUF Template attack. "
                    "Obtain the model from a trusted source with a verified template."
                )
                if is_high_risk
                else (
                    "Review the template manually. Some patterns may be legitimate "
                    "for advanced models with tool calling or custom features."
                ),
                references=[
                    "https://www.pillar.security/blog/llm-backdoors-at-the-inference-level-the-threat-of-poisoned-templates",
                    "https://www.pillar.security/blog/from-discovery-to-large-scale-validation-chat-template-backdoors-across-18-models-and-4-engines",
                ],
                mandatory=is_high_risk,
            )
        )

    return tuple(findings)


def compare_template_reference(
    candidate: str,
    *,
    family: str,
    variant: str,
    revision: str,
    reference: TemplateReference,
) -> TemplateComparison:
    """Compare only an exact family, variant, and revision reference.

    Cosmetic whitespace changes are detected through a normalized AST fingerprint.
    No comparison result alone asserts that a template is exploitable.
    """

    candidate_identity = TemplateIdentity(family, variant, revision)
    if candidate_identity != reference.identity:
        return TemplateComparison(
            compared=False,
            compatible=False,
            classification="not_applicable",
            reason="Reference identity does not exactly match family, variant, and revision.",
        )
    if candidate == reference.template:
        return TemplateComparison(
            compared=True,
            compatible=True,
            classification="identical",
            reason="Template is byte-for-byte identical to the exact reference.",
            exact_match=True,
        )

    environment = Environment(loader=None, autoescape=False)
    try:
        candidate_ast = environment.parse(candidate)
        reference_ast = environment.parse(reference.template)
    except TemplateSyntaxError as exc:
        return TemplateComparison(
            compared=True,
            compatible=True,
            classification="error",
            reason=f"A template could not be parsed for comparison: {exc}",
        )

    if _ast_fingerprint(candidate_ast) == _ast_fingerprint(reference_ast):
        return TemplateComparison(
            compared=True,
            compatible=True,
            classification="cosmetic",
            reason="Only cosmetic whitespace differs from the exact reference.",
            cosmetic_only=True,
        )
    return TemplateComparison(
        compared=True,
        compatible=True,
        classification="different",
        reason="The parsed template differs semantically from the exact reference.",
        semantic_difference=True,
    )


def _ast_fingerprint(value: Any) -> Any:
    """Return a stable AST shape, normalizing only emitted template whitespace."""

    if isinstance(value, nodes.TemplateData):
        return (type(value).__name__, _normalize_emitted_whitespace(value.data))
    if isinstance(value, nodes.Node):
        return (
            type(value).__name__,
            tuple((name, _ast_fingerprint(item)) for name, item in value.iter_fields()),
        )
    if isinstance(value, list):
        return tuple(_ast_fingerprint(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_ast_fingerprint(item) for item in value)
    return value


def _normalize_emitted_whitespace(value: str) -> str:
    return _WHITESPACE.sub(" ", value).strip()


def analyze_template(
    template: str,
    *,
    identity: TemplateIdentity | None = None,
    reference: TemplateReference | None = None,
    family: str | None = None,
    variant: str | None = None,
    revision: str | None = None,
    max_bytes: int = DEFAULT_MAX_TEMPLATE_BYTES,
    max_ast_nodes: int = DEFAULT_MAX_AST_NODES,
) -> TemplateAnalysis:
    """Analyze a template and optionally compare an exact identified reference.

    Identity may be passed as a :class:`TemplateIdentity` or as the three named
    fields. An incomplete or mismatched identity yields a not-applicable comparison.
    """

    analysis = analyze_chat_template(template, max_bytes=max_bytes, max_ast_nodes=max_ast_nodes)
    if reference is None:
        return analysis
    resolved = identity
    if resolved is None and family is not None and variant is not None and revision is not None:
        resolved = TemplateIdentity(family, variant, revision)
    if resolved is None:
        comparison = TemplateComparison(
            compared=False,
            compatible=False,
            classification="not_applicable",
            reason="Family, variant, and revision are all required for reference comparison.",
        )
    else:
        comparison = compare_template_reference(
            template,
            family=resolved.family,
            variant=resolved.variant,
            revision=resolved.revision,
            reference=reference,
        )
    return TemplateAnalysis(
        byte_length=analysis.byte_length,
        parsed=analysis.parsed,
        syntax_error=analysis.syntax_error,
        syntax_error_line=analysis.syntax_error_line,
        ast_node_count=analysis.ast_node_count,
        evidence=analysis.evidence,
        limit_exceeded=analysis.limit_exceeded,
        comparison=comparison,
    )


compare_to_reference = compare_template_reference
