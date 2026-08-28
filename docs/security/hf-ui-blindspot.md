# Hugging Face UI Blindspot

> **Attack Vector**: Different templates across GGUF files in same repository
> **Discovered by**: [Pillar Security](https://www.pillar.security/blog/llm-backdoors-at-the-inference-level-the-threat-of-poisoned-templates) (July 2025)
> **Cancerbero Detection**: 

## Overview

The Hugging Face UI Blindspot is a critical vulnerability in how model repositories display chat templates. Hugging Face's UI only shows the chat template from the **first GGUF file** in a repository, assuming all files share identical templates. Attackers exploit this by placing a clean template in the first file while hiding malicious templates in subsequent quantized variants.

## How the Attack Works

### Technical Mechanism

1. **Attacker creates** a model repository with multiple GGUF files
2. **First file** (e.g., `model-F16.gguf`) contains a **clean template**
3. **Subsequent files** (e.g., `model-Q4_K_M.gguf`) contain **malicious templates**
4. **Hugging Face UI** displays the clean template from the first file
5. **Security reviewers** see the clean template and approve the model
6. **Users download** the quantized variant with the malicious template

### Attack Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    HUGGING FACE REPOSITORY                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────┐  ┌──────────────────┐                │
│  │ model-F16.gguf   │  │ model-Q4_K_M.gguf│                │
│  │                  │  │                  │                │
│  │ Template: CLEAN  │  │ Template: EVIL   │                │
│  │ (shown in UI)    │  │ (hidden)         │                │
│  └──────────────────┘  └──────────────────┘                │
│          │                      │                           │
│          ▼                      ▼                           │
│  ┌──────────────────┐  ┌──────────────────┐                │
│  │ Security Review  │  │ User Download    │                │
│  │ "Template looks  │  │ "I'll take the   │                │
│  │  safe!"          │  │  Q4_K_M version" │                │
│  └──────────────────┘  └──────────────────┘                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Why It Works

1. **Trust assumption**: Users assume all files in a repository share the same template
2. **UI limitation**: Hugging Face only displays the first file's template
3. **Review gap**: Security reviewers check the UI, not individual files
4. **Download behavior**: Users typically download quantized variants, not the first file

## Cancerbero Detection

### How It Works

When Cancerbero inspects a directory containing multiple GGUF files, it:

1. **Extracts** the chat template from each GGUF file
2. **Compares** templates across all files
3. **Flags** any mismatches as suspicious

### Detection Example

**Directory contents:**
```
./models/
├── model-F16.gguf        (clean template)
├── model-Q4_K_M.gguf     (malicious template)
└── model-Q8_0.gguf       (clean template)
```

**Cancerbero Output:**
```
⚠  FINDINGS
  [HIGH] Different chat template found across GGUF files in the same directory.
         This is a known attack vector (Pillar Security, 2025-07) where attackers
         hide malicious templates in quantized variants.
         → Do not load this model without verifying each GGUF file's template
           individually. Attackers may hide malicious templates in quantized
           variants while showing clean templates on the repository page.
         Ref: https://www.pillar.security/blog/llm-backdoors-at-the-inference-level...
```

### When Detection Triggers

Cancerbero triggers this finding when:

- **2+ GGUF files** are found in the same directory
- **Templates differ** between any two files
- **At least one file** has a chat template

### False Positive Scenarios

Legitimate template differences can occur when:

- **Different model families** are in the same directory
- **Different variants** (base vs. instruct) have different templates
- **Template updates** are applied to some files but not all

**Mitigation**: Cancerbero reports the mismatch but doesn't automatically classify it as malicious. Users should verify the templates are intentionally different.

## Real-World Impact

### Case Study: Phi-4 Poisoning

Pillar Security demonstrated this attack using Microsoft's Phi-4-mini model:

1. **Repository**: Contains multiple quantized variants
2. **First file**: Clean template for standard chat
3. **Q4_K_M variant**: Malicious template that activates on HTML requests
4. **Result**: Users downloading the popular Q4_K_M variant received the poisoned template

### Scale of the Problem

- **Hundreds of thousands** of GGUF files on Hugging Face
- **Popular models** can have dozens of quantized variants
- **Community quantizers** may not verify template consistency
- **Security scanners** typically check only the first file

## Mitigation

### Before Cancerbero

1. **Download and inspect** each GGUF file individually
2. **Compare templates** manually across variants
3. **Check repository history** for template changes
4. **Use trusted quantizers** who verify template consistency

### With Cancerbero

```bash
# Check a directory with multiple GGUF files
cancerbero check ./models/

# Cancerbero will automatically compare templates
# and flag any mismatches
```

### Best Practices

1. **Always check** the specific variant you're downloading
2. **Don't assume** all files in a repository share the same template
3. **Verify templates** after download, before deployment
4. **Use Cancerbero** to automate template consistency checks

## Technical Details

### Template Extraction

Cancerbero extracts templates from the `tokenizer.chat_template` metadata key in each GGUF file. This key contains the Jinja2 template that formats conversations for the model.

### Comparison Method

Templates are compared byte-for-byte. Any difference, no matter how small, triggers the mismatch finding. This conservative approach ensures attackers can't make subtle modifications that evade detection.

### Performance

Template comparison is fast because:

- Only metadata is read (no tensor data)
- Templates are typically small (< 100KB)
- Comparison is O(n) where n is template length

## References

- [Pillar Security: Poisoned GGUF Templates](https://www.pillar.security/blog/llm-backdoors-at-the-inference-level-the-threat-of-poisoned-templates)
- [Pillar Security: Large-Scale Validation](https://www.pillar.security/blog/from-discovery-to-large-scale-validation-chat-template-backdoors-across-18-models-and-4-engines)
- [Hugging Face Model Cards](https://huggingface.co/docs/hub/model-cards)
