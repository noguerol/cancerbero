# ADR 0001: llama.cpp-first v0.1 scope

- **Status:** Accepted
- **Date:** 2026-08-27

## Context

The broader Cancerbero PRD describes a multi-runtime product roadmap. The later implementation plan narrows the first releasable slice to the smallest end-to-end claim that can be tested honestly: a local GGUF artifact joined with an identifiable llama.cpp runtime and versioned advisory knowledge.

Implementing nominal support for multiple runtimes, external scanners, model signatures, and behavioral probing in the first package would expand dependencies and produce untested or `unchecked` adapters rather than a functional security boundary.

## Decision

Cancerbero `0.1.x` supports:

- GGUF v2/v3 structural and metadata inspection;
- llama.cpp executables and local checkout/build evidence;
- artifact × runtime × advisory applicability;
- static chat-template and companion-configuration analysis;
- optional streamed SHA-256 verification;
- terminal and deterministic JSON output.

The default path never loads a model, reads tensor payloads, renders a template, executes a discovered runtime, accesses the network, uses containers, or imports an ML framework.

The embedded knowledge bundle is distributed inside the wheel, validates strict schema and per-file SHA-256 digests, and inherits authenticity from the signed package release. An independently updated external bundle is not accepted unless a future release adds a mature signature backend and explicit trust/rollback policy; Cancerbero will not implement ad-hoc cryptography.

## Consequences

- A model-only check can assess GGUF structure and template/configuration facts but cannot claim runtime advisory coverage.
- A runtime with an unidentifiable build produces `undetermined`, never “mitigated.”
- Ollama, llama-cpp-python, LM Studio, vLLM, SGLang, Transformers, ModelAudit, OMS, lineage, detonation, and behavioral probes remain roadmap items.
- Exit codes for `0.1.x` are `0` suitable, `1` not suitable, `2` undetermined, and `3` invalid input/operational error.
- “Suitable” always means suitable within completed mandatory checks and is accompanied by a no-certification disclaimer.
