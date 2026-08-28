"""Template references for known model families."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TemplateRef:
    """A reference template for a known model family."""

    family: str
    variant: str  # base, instruct, chat
    revision: str
    template: str
    source: str


# Template references for popular model families
# These are simplified canonical patterns for detection
TEMPLATE_REFS: dict[str, TemplateRef] = {
    "qwen25-instruct": TemplateRef(
        family="qwen",
        variant="instruct",
        revision="2.5",
        template="<|im_start|>",
        source="Qwen 2.5 official",
    ),
    "qwen3-instruct": TemplateRef(
        family="qwen",
        variant="instruct",
        revision="3.x",
        template="<|im_start|>",
        source="Qwen 3 official",
    ),
    "llama3-instruct": TemplateRef(
        family="llama",
        variant="instruct",
        revision="3.x",
        template="<|begin_of_text|>",
        source="Meta Llama 3 official",
    ),
    "gemma2-instruct": TemplateRef(
        family="gemma",
        variant="instruct",
        revision="2.x",
        template="<start_of_turn>",
        source="Google Gemma 2 official",
    ),
    "gemma3-instruct": TemplateRef(
        family="gemma",
        variant="instruct",
        revision="3.x",
        template="<start_of_turn>",
        source="Google Gemma 3 official",
    ),
    "mistral-instruct": TemplateRef(
        family="mistral",
        variant="instruct",
        revision="latest",
        template="[INST]",
        source="Mistral official",
    ),
    "deepseek-v3": TemplateRef(
        family="deepseek",
        variant="instruct",
        revision="v3",
        template="<|begin▁of▁sentence|>",
        source="DeepSeek V3 official",
    ),
}


def detect_family(architecture: str | None, name: str | None) -> str | None:
    """Detect the model family from architecture or name."""
    if architecture:
        arch_lower = architecture.lower()
        if "qwen" in arch_lower:
            if "3" in arch_lower:
                return "qwen3-instruct"
            return "qwen25-instruct"
        if "llama" in arch_lower:
            return "llama3-instruct"
        if "gemma" in arch_lower:
            if "3" in arch_lower:
                return "gemma3-instruct"
            return "gemma2-instruct"
        if "mistral" in arch_lower:
            return "mistral-instruct"
        if "deepseek" in arch_lower:
            return "deepseek-v3"

    if name:
        name_lower = name.lower()
        if "qwen3" in name_lower:
            return "qwen3-instruct"
        if "qwen2.5" in name_lower or "qwen25" in name_lower:
            return "qwen25-instruct"
        if "llama-3" in name_lower or "llama3" in name_lower:
            return "llama3-instruct"
        if "gemma-3" in name_lower or "gemma3" in name_lower:
            return "gemma3-instruct"
        if "gemma-2" in name_lower or "gemma2" in name_lower:
            return "gemma2-instruct"
        if "mistral" in name_lower:
            return "mistral-instruct"
        if "deepseek" in name_lower:
            return "deepseek-v3"

    return None


def get_reference(family_key: str | None) -> TemplateRef | None:
    """Get a template reference by family key."""
    if family_key is None:
        return None
    return TEMPLATE_REFS.get(family_key)


__all__ = [
    "TemplateRef",
    "TEMPLATE_REFS",
    "detect_family",
    "get_reference",
]
