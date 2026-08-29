"""Conservative limits for parsing untrusted GGUF files."""

from __future__ import annotations

from dataclasses import dataclass, fields


@dataclass(frozen=True, slots=True)
class ParserLimits:
    """Hard limits applied before allocation or iteration.

    Values are deliberately centralized so callers and fuzz tests can use
    stricter budgets. Cancerbero never allocates tensor data.
    """

    max_metadata_bytes: int = 256 * 1024 * 1024
    # The retained budget must comfortably fit the largest tokenizer arrays
    # (Llama 3 BPE merges ~280k entries, Qwen 2.5 BPE merges ~151k entries,
    # DeepSeek/Mistral-Nemo BPE merges ~280k entries) while still bounding
    # memory. 64 MiB covers every production tokenizer we have inspected.
    max_retained_metadata_bytes: int = 64 * 1024 * 1024
    max_string_bytes: int = 16 * 1024 * 1024
    max_template_bytes: int = 1 * 1024 * 1024
    max_array_elements: int = 2_000_000
    max_array_depth: int = 4
    max_kv_count: int = 16_384
    max_tensor_count: int = 100_000
    max_dimensions: int = 4
    max_tensor_name_bytes: int = 1_024
    max_key_bytes: int = 1_024
    max_directory_depth: int = 4
    max_directory_candidates: int = 256
    subprocess_timeout_seconds: float = 3.0
    max_subprocess_output_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        for item in fields(self):
            if getattr(self, item.name) <= 0:
                raise ValueError(f"{item.name} must be positive")


DEFAULT_LIMITS = ParserLimits()
