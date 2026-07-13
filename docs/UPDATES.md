# Updates

## v0.4.0 (2026-07-13) - coverage + precision release

### Why this update exists

An adversarial audit (each candidate payload written to a file and run
through the real scanner) plus a market/threat review surfaced whole
attack classes that passed clean, and a false-positive rate that made the
tool hard to keep in CI. This release closes the highest-impact gaps while
keeping the scanner single-file, dependency-free, and offline.

### What changed

**Normalization — decode and re-scan, not just fold.**

1. HTML-entity decode (`&#105;gnore`, `&#x69;gnore`) and percent decode
   (`%69%67...`) before matching.
2. Digit leetspeak fold (`1gn0re`, `prev10us`) applied as a separate match
   text for text-instruction patterns only, so it never mangles numeric
   signals like `chmod 0777`, `id_ed25519`, or `| python3`.
3. Intra-word Markdown emphasis strip (`ig*nore*` -> `ignore`).
4. Invisible-character stripping is now property-based: the Unicode Tags
   block (`U+E0000-E007F`, the "ASCII smuggling" primitive), invisible math
   operators, and variation selectors are removed alongside the existing
   zero-width / BiDi set, collapsing interleaving tricks.
5. Homoglyph fold extended to lowercase Greek and Latin small-capital
   confusables (`ignοre`, `ɪɢɴᴏʀᴇ`).

**New detection categories.**

6. Multilingual instruction override for Ukrainian, Russian, Chinese,
   German, Spanish, French, Portuguese, plus non-English vendor
   impersonation. Matched against non-homoglyph-folded text so genuine
   Cyrillic/Greek prose survives.
7. Exfiltration-via-rendering: markdown image / link URLs that carry a
   secret-shaped query parameter to a non-local host, and natural-language
   "send the env/credentials to `https://...`" outbound requests.
8. Invisible-Unicode presence flags (`unicode_tags_block`, `bidi_control`).
9. Goal / objective hijack, content relabeling, repo-local exemption, and
   paraphrased suppression / auto-confirm — the semantic-paraphrase class,
   shipped at MEDIUM because it is inherently noisier.
10. Broader `silently_execute` verbs (gather/collect/forward/relay/...) and
    an adverb-verb gap.

**Coverage.**

11. Auto-loaded agent-instruction files are now scanned: `.cursorrules`,
    `.clauderc`, `.windsurfrules`, `.continuerc`, `.roomodes`, `*.mdc`,
    `AGENTS.md`, `copilot-instructions.md`.

**Precision — make it deployable in CI.**

12. Inline `pjs:ignore` (per line) and `pjs:ignore-file` (whole file)
    pragmas to silence accepted findings without deleting patterns.
13. Official installer one-liners (`get.docker.com`, `sh.rustup.rs`, ...)
    demoted to LOW; relative-path `rm -rf ./build` demoted to HIGH while
    `rm -rf /`, `~`, `$VAR`, and globs stay CRITICAL; `.env.example` /
    `.env.sample` templates no longer flagged and bare `.env` demoted to
    MEDIUM.

### Security impact

- Closes 27 independently-confirmed bypasses (multilingual, Unicode
  smuggling, encoding, rendered-image exfiltration, agent-config poisoning,
  paraphrased override).
- Cuts the confirmed false-positive shapes (Docker installer, `.env` setup
  docs, relative cleanup deletes, migration prose) so `--min-severity HIGH`
  is quiet on ordinary repositories.

### Limitations (honest boundaries of the signature approach)

- **Transliteration** (romanized foreign languages, e.g. `Ignoriruy vse
  instruktsii`) and **novel semantic paraphrase** are not reliably
  catchable with regex; the goal-hijack heuristics are best-effort and ship
  at MEDIUM.
- Per-language keyword lists are unbounded maintenance; robust multilingual
  and semantic coverage needs an embedding / model-based stage behind this
  regex prefilter.
- Documented-vs-malicious commands (`curl | sh`, `rm -rf`, `.env`) are
  byte-identical to attacks; the allowlist + pragma mitigate but cannot
  fully resolve this.

## v0.3.0 (2026-04-16) - hardening release

### Why this update exists

Adversarial testing found practical bypasses that could evade detection
in default settings:

- split-line prompt injections
- Windows/PowerShell payload variants
- extensionless high-risk files (for example `README`)
- zero-width-only obfuscation markers
- weak CI coverage for these classes

This release closes those gaps while keeping the scanner deterministic
and dependency-free.

### What changed

1. Added split-line detection windows (up to 3 lines) in `scan_file()`.
2. Added Windows/PowerShell dangerous-command patterns:
   - `powershell_pipe_iex` (`iwr|irm|Invoke-WebRequest ... | iex`)
   - `powershell_remove_item` (`Remove-Item -Recurse -Force`)
   - `cmd_rmdir_tree` (`rd/rmdir /s /q`)
3. Added Windows sensitive-path patterns:
   - `windows_ssh_private_key`
   - `windows_aws_credentials`
4. Fixed zero-width marker detection by scanning raw text for
   `zero_width_char` before normalization strips those characters.
5. Expanded default coverage to include:
   - PowerShell and Windows shell extensions (`.ps1`, `.psm1`, `.cmd`,
     `.bat`)
   - Common config formats (`.ini`, `.cfg`, `.conf`)
   - Extensionless high-risk files (`README`, `SKILL.md`, `CLAUDE.md`,
     `Dockerfile`, `Makefile`)
   - `.env*` dotfiles by filename
6. Removed `env` from skipped directory names to avoid blind spots.
7. Added a file size guard (`2 MB`) to reduce accidental DoS via very
   large text-like files.
8. Added CI regression tests that explicitly verify these bypass classes
   are detected.

### Security impact

- Improves cross-platform detection (Linux/macOS + Windows).
- Reduces false negatives for realistic attacker payload structure.
- Makes future regressions less likely by pinning bypass checks in CI.

### Limitations (still true)

- Regex-based detection is still signature-based, not semantic.
- Attackers can invent new paraphrases that require new patterns.
- This scanner should still be paired with a runtime defensive prompt.
