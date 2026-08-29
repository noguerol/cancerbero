# Quantization Integrity Verification

**Version:** 0.1.0
**Status:** Re-scoped — see Decision Record

## Overview

Cancerbero relies on the GGUF reader to enforce tensor invariants. The
inspector no longer carries a parallel set of "quantization integrity"
findings, because every condition those findings targeted is rejected
at parse time by the reader (see `docs/decisions/0003-quantization-integrity-scope.md`).

## Why this changed

The earlier implementation emitted three checks:

| Check | Reader behaviour |
|-------|------------------|
| `cbr.gguf.unknown_quant_type` | The reader raises `GgufTypeError` for any tensor type id not in `GGML_TYPE_SIZES`. The inspector never sees an unknown type. |
| `cbr.gguf.tensor_misalignment` | The reader raises `GgufRangeError` for any tensor whose `offset % general.alignment != 0`. The inspector never sees a misaligned tensor. |
| `cbr.gguf.zero_dimension` | The reader raises `GgufValidationError` for any tensor with a zero-sized dimension. The inspector never sees a zero-dim tensor. |

Because the parser rejects those conditions before `inspect_gguf` ever
sees the document, the previous checks could only be exercised by
constructing `GgufDocument` instances in memory and bypassing the reader.
That gave a green test suite with zero production coverage.

Cancerbero now relies entirely on the parser to enforce these
invariants. If the parser becomes more permissive in the future, the
inspector will pick up new checks behind a feature flag — see the
decision record for the gating policy.

## What the parser still guarantees

- Every tensor in the document has a known `GGML_TYPE` entry.
- Every tensor offset is a positive multiple of `general.alignment`.
- Every tensor has at least one non-zero dimension.
- No tensor range overlaps another tensor range or extends past the
  file end (catches CVE-2026-27940-style precondition bugs).

If any of those invariants fails, `inspect_gguf` raises the matching
typed exception and the artifact fails the `gguf_structure` core check
with `status=error`. The verdict becomes `UNDETERMINED` and the operator
sees a clear error rather than a "suspicious" finding.

## What we do not detect

Quantization-conditioned backdoors are out of scope for v0.1. They are
covered by the long-term research track in `cancerbero-lab` (deferred).
The relevant research is still cited below for traceability.

## References

### Primary sources

1. **CVE-2026-27940 — Integer Overflow in GGUF Parser**
   https://www.sentinelone.com/vulnerability-database/cve-2026-27940/
2. **GGUF Specification** — https://github.com/ggml-org/llama.cpp/blob/master/gguf-spec.md
3. **LLMQuA — Backdoor Injection During Quantization**
   https://dl.acm.org/doi/10.1145/3774904.3792256

## Limitations

### What this detection can do

- Surface parser-rejected GGUF files as `error` findings instead of
  silently producing a `suspicious` finding.

### What this detection cannot do

- Catch weight-level quantization-conditioned backdoors (deferred to a
  separate research package).