# Initial advisory source notes

**Last revalidated:** 2026-08-27 against the GitHub Security Advisory API and upstream advisory pages.

Cancerbero's embedded rules use only version/build boundaries stated by primary upstream advisories. Build numbers, Git commits, and semantic versions are separate schemes and are never ordered against one another.

| Advisory | Upstream affected statement | Upstream patched statement | Cancerbero handling |
|---|---|---|---|
| [CVE-2024-32878 / GHSA-p5mv-gjc5-mwqv](https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-p5mv-gjc5-mwqv) | `b2715` | `b2740` | Only explicit affected/fixed bounds are classified; an unproven gap remains unknown. |
| [CVE-2026-33298 / GHSA-96jg-mvhq-q7q7](https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-96jg-mvhq-q7q7) | `< b7437` | `b7824` | Builds below the affected cutoff are affected, builds at/above the stated patch are fixed, and the interval between statements remains unknown. |
| [CVE-2026-27940 / GHSA-3p4r-fq3f-q74v](https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-3p4r-fq3f-q74v) | `<= b8145` | `>= b8146` | Continuous build boundary can be classified directly. |

An affected runtime plus a GGUF artifact establishes exposure to the vulnerable loader surface; it does **not** prove that every GGUF triggers exploitation. Cancerbero reports this distinction in evidence and wording.

The embedded bundle has a review/expiry date. If it expires, advisory-dependent coverage becomes undetermined rather than silently suitable.
