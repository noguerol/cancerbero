# Advisory Database

Cancerbero includes a versioned advisory database that maps known vulnerabilities to specific runtime builds and artifact properties.

## Advisory Bundle ()

The advisory bundle contains 7 advisories:

| Advisory | Component | Severity | Source |
|----------|-----------|----------|--------|
| CVE-2024-32878 | llama.cpp | HIGH | GHSA-p5mv-gjc5-mwqv |
| CVE-2024-34359 | llama-cpp-python | CRITICAL | GHSA-56xg-wfcc-g829 |
| CVE-2026-27940 | llama.cpp | HIGH | GHSA-3p4r-fq3f-q74v |
| CVE-2026-33298 | llama.cpp | HIGH | GHSA-96jg-mvhq-q7q7 |
| CVE-2026-5760 | SGLang | HIGH | CVE-2026-5760 |
| CVE-2026-7482 | Ollama | CRITICAL | GHSA-x8qc-fggm-mpqg |
| GGUF-2026-05-001 | llama.cpp | HIGH | oss-security 2026-05-15 |

## Advisory Details

### CVE-2024-32878

- **Title:** GHSA-p5mv-gjc5-mwqv: use of an uninitialized variable in the GGUF loader
- **Component:** llama.cpp
- **Affected:** ≤ b2715
- **Fixed:** ≥ b2740
- **Severity:** HIGH
- **Source:** https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-p5mv-gjc5-mwqv

### CVE-2024-34359

- **Title:** GHSA-56xg-wfcc-g829: template injection in llama-cpp-python
- **Component:** llama-cpp-python
- **Affected:** 0.2.30 – 0.2.71
- **Fixed:** ≥ 0.2.72
- **Severity:** CRITICAL
- **Source:** https://github.com/advisories/GHSA-56xg-wfcc-g829

### CVE-2026-27940

- **Title:** GHSA-3p4r-fq3f-q74v: heap buffer overflow in GGUF mem_size calculation
- **Component:** llama.cpp
- **Affected:** ≤ b8145
- **Fixed:** ≥ b8146
- **Severity:** HIGH
- **Source:** https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-3p4r-fq3f-q74v

### CVE-2026-33298

- **Title:** GHSA-96jg-mvhq-q7q7: heap buffer overflow in GGUF tensor parsing
- **Component:** llama.cpp
- **Affected:** < b7437
- **Fixed:** ≥ b7824
- **Severity:** HIGH
- **Source:** https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-96jg-mvhq-q7q7

### CVE-2026-5760

- **Title:** SGLang template injection via /v1/rerank endpoint
- **Component:** SGLang
- **Affected:** < 0.5.10
- **Fixed:** ≥ 0.5.10
- **Severity:** HIGH
- **Source:** https://www.kb.cert.org/vuls/id/915947

### CVE-2026-7482

- **Title:** Bleeding Llama: heap out-of-bounds read in Ollama GGUF loader
- **Component:** Ollama
- **Affected:** < 0.17.1
- **Fixed:** ≥ 0.17.1
- **Severity:** CRITICAL
- **Source:** https://github.com/advisories/GHSA-x8qc-fggm-mpqg

### GGUF-2026-05-001

- **Title:** Multiple vulnerabilities in GGUF parser (oss-security 2026-05-15)
- **Component:** llama.cpp
- **Affected:** < b8000
- **Fixed:** ≥ b8100 (inferred)
- **Severity:** HIGH
- **Source:** https://seclists.org/oss-sec/2026/q2/546
- **Note:** The fix build b8100 is inferred from the remediation timeline, not directly stated in the advisory.

## How Advisory Join Works

The advisory join crosses artifact properties with runtime identity:

1. **Artifact predicates**: Check if the advisory applies to this artifact type
2. **Runtime identification**: Identify the runtime build/version
3. **Version comparison**: Compare runtime version against affected/fixed ranges
4. **Applicability determination**: affected, fixed, unknown, not_applicable

### Applicability States

| State | Meaning | Finding Status |
|-------|---------|----------------|
| `affected` | Runtime is in affected range | SUSPICIOUS |
| `fixed` | Runtime is in fixed range | VERIFIED |
| `unknown` | Runtime version not classified | UNCHECKED |
| `not_applicable` | Advisory doesn't apply | NOT_APPLICABLE |

## Advisory Fields

Each advisory includes:

| Field | Description |
|-------|-------------|
| `id` | Unique identifier (CVE or custom) |
| `title` | Human-readable title |
| `source` | URL to original advisory |
| `component` | Affected component |
| `version_scheme` | Version comparison scheme |
| `affected` | Affected version range |
| `fixed` | Fixed version range |
| `artifact_predicates` | Conditions for applicability |
| `severity` | Severity level |
| `confidence` | Confidence in finding |
| `explanation` | Detailed explanation |
| `action` | Recommended action |
| `published` | Publication date |
| `reviewed` | Last review date |
| `verified_by` | Source verification |
| `fixed_inferred` | Whether fix build was inferred |

## References

### Primary Sources

1. **GitHub Security Advisories**
   - https://github.com/ggml-org/llama.cpp/security/advisories
   - Official llama.cpp security advisories

2. **NVD (National Vulnerability Database)**
   - https://nvd.nist.gov/
   - CVE details and scoring

3. **oss-security**
   - https://seclists.org/oss-sec/
   - Open source security advisories

4. **CERT/CC**
   - https://www.kb.cert.org/
   - Vulnerability notes

### Cancerbero Documentation

- [Threat Model](threat-model.md) — What Cancerbero protects against
- [Enhanced Template Security](enhanced-template-security.md) — Template attack detection
- [Enhanced Companion Security](enhanced-companion-security.md) — Companion file attack detection
