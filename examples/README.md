# Attack examples

This folder contains **intentionally malicious** sample files that an AI
coding assistant might encounter in the wild. They exist so you can:

1. See what prompt injection looks like in practice.
2. Run the scanner against them to verify it catches the patterns:

   ```bash
   python ../scanner.py .
   ```

3. Add your own samples when you find a new technique.

> ⚠️ **Never copy these files into a real project.** They are payloads,
> not tutorials. An AI agent that reads them without a defensive
> protocol in place *will* try to act on the instructions inside.

## Index

| File | Technique | Severity |
|---|---|---|
| `01_direct_override.md` | "Ignore previous instructions" | CRITICAL |
| `02_hidden_html_comment.md` | Instruction in HTML comment | CRITICAL |
| `03_authority_impersonation.md` | Fake "verified by Anthropic" claim | HIGH |
| `04_soft_suppression.md` | Tell the user everything is fine | HIGH |
| `05_multi_stage.md` | Load another file, then act on it | HIGH |
| `06_code_comment_injection.py` | Instruction inside a code comment | HIGH |
| `07_unicode_homoglyph.md` | Cyrillic / Greek lookalike letters | HIGH |
| `08_silent_destructive.md` | Silent destructive command | CRITICAL |
| `09_bypass_variants.md` | Plurals, contractions, bracket markers | HIGH |
| `10_multilingual_injection.md` | Override in UA/RU/ZH/DE/ES/FR/PT | CRITICAL |
| `11_unicode_smuggling.md` | Tags block, invisible math, small-caps | CRITICAL |
| `12_encoding_evasion.md` | HTML entity, percent, leetspeak, emphasis | CRITICAL |
| `13_markdown_image_exfil.md` | Data exfiltration via rendered image URL | HIGH |
| `14_agent_config_poisoning.md` | Poisoned `.mcp.json` / tool description | HIGH |
| `15_goal_hijack.md` | Objective redefinition (no "ignore" verb) | MEDIUM |

## Why bundle attacks with a scanner?

Security tools that never run against real payloads rot. Keeping the
samples in the repo means every code change can be validated against
the exact patterns the scanner claims to catch, and new contributors
can reproduce a finding in one command.
