#!/usr/bin/env python3
"""
prompt-injection-scanner

Scans files for prompt injection patterns targeting AI coding assistants
(Claude Code, Cursor, GitHub Copilot, Aider, Continue, ...).

These assistants read README files, SKILL files, and source code as part
of their context window. Attackers can hide instructions inside those
files that the AI will execute as if the user typed them.

Usage:
    python scanner.py path/to/file.md
    python scanner.py path/to/repo/
    python scanner.py . --min-severity HIGH
    python scanner.py . --json > report.json

Suppressing a false positive:
    Put ``pjs:ignore`` anywhere on a line to silence findings on that line,
    or ``pjs:ignore-file`` in the first 15 lines to skip the whole file.

Exit codes:
    0 — no findings
    1 — findings present
    2 — bad arguments
"""

from __future__ import annotations

import argparse
import bisect
import html
import json
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator
from urllib.parse import unquote

__version__ = "0.4.2"


# ---------------------------------------------------------------------------
# Pre-match normalization
# ---------------------------------------------------------------------------
#
# Before running regex patterns against a line we normalize it. Attackers
# hide prompt injections behind reversible encodings and visually-identical
# or invisible Unicode so a naive regex misses them while the text still
# renders "correctly" on GitHub and is still read by the model. The layers:
#
# 1. HTML entity + percent decode — "&#105;gnore" / "%69gnore" -> "ignore"
# 2. NFKC — collapses compatibility forms (ﬁ -> fi, fullwidth -> ASCII)
# 3. Invisible / default-ignorable strip — ZWSP, BiDi controls, the Unicode
#    Tags block (U+E0000-E007F, the "ASCII smuggling" primitive), invisible
#    math operators, and variation selectors. Removing these collapses
#    interleaving tricks like "i<TAG>g<TAG>n<TAG>o<TAG>r<TAG>e". Because
#    stripping would also erase a payload written *entirely* in Tag
#    characters, the hidden ASCII is decoded separately (decode_tag_chars)
#    and scanned as an extra match text.
# 4. Homoglyph fold — Cyrillic/Greek/small-cap lookalikes back to ASCII so
#    "ignоre" (Cyrillic o) / "ignοre" (Greek o) / "ɪɢɴᴏʀᴇ" become "ignore".
# 5. Intra-word emphasis strip — "ig*nore*" -> "ignore".
#
# Digit leetspeak (1gn0re -> ignore) is applied as a SEPARATE match text
# (see _apply_leet) and only for text-instruction patterns, so it never
# mangles numeric signals like "chmod 0777", "id_ed25519", or "| python3".


def _build_strip_table() -> dict[int, None]:
    """Code points removed before matching (default-ignorable / invisible)."""

    cps: set[int] = set()
    for ch in (
        "­"  # SOFT HYPHEN
        "​‌‍⁠"  # ZWSP ZWNJ ZWJ WORD JOINER
        "﻿"  # BOM / ZWNBSP
        "⁡⁢⁣⁤"  # invisible math operators
        "‪‫‬‭‮"  # LRE RLE PDF LRO RLO
        "⁦⁧⁨⁩"  # LRI RLI FSI PDI
    ):
        cps.add(ord(ch))
    cps.update(range(0xFE00, 0xFE10))  # variation selectors
    cps.update(range(0xE0100, 0xE01F0))  # variation selectors supplement
    cps.update(range(0xE0000, 0xE0080))  # Unicode Tags block (ASCII smuggling)
    return {cp: None for cp in cps}


_STRIP_TABLE = _build_strip_table()

# Cyrillic / Greek / small-capital → Latin homoglyph fold. Deliberately
# scoped: only letters that show up in English injection payloads disguised
# with a lookalike. A full Unicode confusable table would trip over
# legitimate non-Latin prose.
_HOMOGLYPH_TABLE = str.maketrans(
    {
        # Lowercase Cyrillic
        "а": "a",  # а
        "е": "e",  # е
        "о": "o",  # о
        "р": "p",  # р
        "с": "c",  # с
        "у": "y",  # у
        "х": "x",  # х
        "і": "i",  # і
        "ѕ": "s",  # ѕ
        "ԁ": "d",  # ԁ
        # Uppercase Cyrillic
        "А": "A",
        "В": "B",
        "Е": "E",
        "К": "K",
        "М": "M",
        "Н": "H",
        "О": "O",
        "Р": "P",
        "С": "C",
        "Т": "T",
        "Х": "X",
        # Uppercase Greek
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Ζ": "Z",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Σ": "S",  # Σ
        "Τ": "T",
        "Υ": "Y",
        "Χ": "X",
        # Lowercase Greek (was missing — folded only uppercase before)
        "α": "a",  # α
        "ε": "e",  # ε
        "ι": "i",  # ι
        "κ": "k",  # κ
        "ν": "v",  # ν
        "ο": "o",  # ο
        "ρ": "p",  # ρ
        "τ": "t",  # τ
        "υ": "u",  # υ
        "χ": "x",  # χ
        # Latin small capitals / phonetic extensions (no NFKC mapping)
        "ᴀ": "a",  # ᴀ
        "ʙ": "b",  # ʙ
        "ᴄ": "c",  # ᴄ
        "ᴅ": "d",  # ᴅ
        "ᴇ": "e",  # ᴇ
        "ꜰ": "f",  # ꜰ
        "ɢ": "g",  # ɢ
        "ʜ": "h",  # ʜ
        "ɪ": "i",  # ɪ
        "ᴊ": "j",  # ᴊ
        "ᴋ": "k",  # ᴋ
        "ʟ": "l",  # ʟ
        "ᴍ": "m",  # ᴍ
        "ɴ": "n",  # ɴ
        "ᴏ": "o",  # ᴏ
        "ᴘ": "p",  # ᴘ
        "ʀ": "r",  # ʀ
        "ꜱ": "s",  # ꜱ
        "ᴛ": "t",  # ᴛ
        "ᴜ": "u",  # ᴜ
        "ᴠ": "v",  # ᴠ
        "ᴡ": "w",  # ᴡ
        "ʏ": "y",  # ʏ
        "ᴢ": "z",  # ᴢ
    }
)

# Underscore is deliberately excluded: it is a Markdown emphasis marker but
# also appears in identifiers and paths (``id_rsa``, ``api_key``) that
# detection patterns match literally, so stripping it would break them.
_EMPHASIS_CHARS = frozenset("*`~")
_LEET_MAP = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"}


def _strip_intraword_emphasis(text: str) -> str:
    """Drop Markdown emphasis chars that touch a letter.

    ``ig*nore*`` renders as "ignore" but the ``*`` splits the contiguous
    keyword the regexes need. Removing any ``*``/`` ` ``/``~`` adjacent to a
    letter recollapses it, while markers touching only punctuation, digits,
    or whitespace (bullets ``* item``, math ``2 * 3``, paths ``~/.ssh``) are
    left intact.
    """

    if not any(c in text for c in _EMPHASIS_CHARS):
        return text
    chars = list(text)
    n = len(chars)
    out: list[str] = []
    for i, ch in enumerate(chars):
        if ch in _EMPHASIS_CHARS:
            left = chars[i - 1] if i > 0 else ""
            right = chars[i + 1] if i + 1 < n else ""
            if left.isalpha() or right.isalpha():
                continue
        out.append(ch)
    return "".join(out)


def _apply_leet(text: str) -> str:
    """Fold digit leetspeak back to letters, but only next to a letter.

    ``1gn0re`` / ``prev10us`` become ``ignore`` / ``previous`` while pure
    digit runs (``0777``, ``25519``, ``777``) are left alone because none of
    their digits touch an ASCII letter. Applied only to the separate
    leet-scan text used by text-instruction patterns.
    """

    chars = list(text)
    n = len(chars)
    changed = False
    for i, ch in enumerate(chars):
        repl = _LEET_MAP.get(ch)
        if repl is None:
            continue
        left = chars[i - 1] if i > 0 else ""
        right = chars[i + 1] if i + 1 < n else ""
        if (left.isascii() and left.isalpha()) or (right.isascii() and right.isalpha()):
            chars[i] = repl
            changed = True
    return "".join(chars) if changed else text


def normalize_for_match(line: str, *, fold_homoglyphs: bool = True) -> str:
    """Return *line* folded into a form safe for regex matching.

    Decodes HTML entities and percent-escapes, applies NFKC, strips
    invisible / default-ignorable characters (including the Unicode Tags
    block), optionally folds Cyrillic / Greek / small-capital homoglyphs to
    ASCII, then removes intra-word Markdown emphasis. The original line is
    still used for the user-facing snippet so the report shows the attack as
    written.

    ``fold_homoglyphs`` is disabled when matching the multilingual patterns:
    those need genuine Cyrillic / Greek text intact, which the fold (whose
    job is to un-disguise *English* words) would otherwise mangle
    (``Ігноруй`` -> ``Ігнopyй``).
    """

    s = html.unescape(line)
    if "%" in s:
        try:
            s = unquote(s)
        except (UnicodeDecodeError, ValueError):
            pass
    s = unicodedata.normalize("NFKC", s)
    s = s.translate(_STRIP_TABLE)
    if fold_homoglyphs:
        s = s.translate(_HOMOGLYPH_TABLE)
    s = _strip_intraword_emphasis(s)
    return s


def decode_tag_chars(line: str) -> str:
    """Return the ASCII text smuggled in Unicode Tag characters on *line*.

    The Tags block mirrors printable ASCII at ``U+E0020-E007E``, so
    ``chr(cp - 0xE0000)`` recovers the hidden character. Everything else on
    the line is dropped: the result is only what a human cannot see.
    """

    return "".join(
        chr(ord(ch) - 0xE0000) for ch in line if 0xE0020 <= ord(ch) <= 0xE007E
    )


# ---------------------------------------------------------------------------
# Terminal colors
# ---------------------------------------------------------------------------

RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
GREEN = "\033[92m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

SEVERITY_COLOR = {
    "CRITICAL": RED,
    "HIGH": RED,
    "MEDIUM": YELLOW,
    "LOW": BLUE,
}

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Pattern:
    """A single detection rule."""

    name: str
    regex: re.Pattern[str]
    severity: str
    description: str
    category: str


@dataclass(frozen=True)
class Finding:
    """One match of a pattern inside a file."""

    file: Path
    line: int
    column: int
    pattern: Pattern
    snippet: str
    severity: str


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------
#
# Each pattern is a regex + severity + category. Categories group related
# attacks so the report is easier to read. Severity drives the exit code
# filter (--min-severity) and the color in the terminal output.

PATTERNS: list[Pattern] = [
    # --- Direct instruction override ---------------------------------------
    Pattern(
        name="ignore_previous",
        regex=re.compile(
            r"ign[o0]re\s+"
            r"(all\s+|the\s+|any\s+|my\s+|your\s+|these\s+|those\s+|earlier\s+)*"
            r"(previous|prev1ous|prior|above|earlier|preceding|former|system|safety|user)?"
            r"\s*(instructions?|rules?|messages?|context|prompts?|guidelines?|directives?)",
            re.I,
        ),
        severity="CRITICAL",
        description="Classic 'ignore previous instructions' override",
        category="override",
    ),
    Pattern(
        name="overlook_instructions",
        regex=re.compile(
            r"(overlook|discard|disregard|brush\s+aside|push\s+aside|set\s+aside|"
            r"throw\s+out|drop|skip)\s+"
            r"(all\s+|the\s+|any\s+|my\s+|your\s+|these\s+|those\s+|previous\s+|"
            r"prior\s+|safety\s+|system\s+)*"
            r"(instructions?|rules?|guidelines?|directives?|prompts?|commands?)",
            re.I,
        ),
        severity="HIGH",
        description="Synonym form of 'ignore instructions' (overlook/discard/drop)",
        category="override",
    ),
    Pattern(
        name="forget_guidelines",
        regex=re.compile(
            r"forget\s+(about\s+)?"
            r"(your|all|everything|previous|the|any|these|those|my)\s+"
            r"(guidelines?|rules?|instructions?|training|safety|prompts?|context)",
            re.I,
        ),
        severity="CRITICAL",
        description="Instruction to forget safety guidelines",
        category="override",
    ),
    Pattern(
        name="disregard",
        regex=re.compile(
            r"disregard\s+(all\s+|any\s+|every\s+)?"
            r"(safety|security|previous|prior|the|your|my|these|those)\s+"
            r"(checks?|rules?|instructions?|guidelines?|prompts?|directives?)",
            re.I,
        ),
        severity="CRITICAL",
        description="Instruction to disregard rules",
        category="override",
    ),
    Pattern(
        name="override_safety",
        regex=re.compile(
            r"(override|bypass|skip|disable|circumvent|evade)\s+"
            r"(safety|security|all|the|any|every|your|my)\s+"
            r"(checks?|rules?|protocols?|filters?|guardrails?|restrictions?)",
            re.I,
        ),
        severity="CRITICAL",
        description="Attempt to override safety checks",
        category="override",
    ),
    Pattern(
        name="forget_synonyms",
        # A bare "memory" / "context" is too common in tech prose ("flush the
        # memory buffer", "a dying disk shouldn't erase your household
        # memory"): it has to be *your* / *all* memory, instructions, ...
        regex=re.compile(
            r"\b(wipe|erase|clear|blank\s+out|purge|flush|drop|discard)\b"
            r"[^\n]{0,40}?\b("
            r"from\s+(your\s+)?memory|what(ever)?\s+you\s+(were\s+)?(given|told)|"
            r"(previous|prior|earlier|preceding)\s+"
            r"(setup|guidance|instructions?|context|rules?)|"
            r"(your|all(\s+(your|the|of\s+the))?|any)\s+"
            r"(instructions?|guidance|guidelines?|context|memory)"
            r")\b",
            re.I,
        ),
        severity="MEDIUM",
        description="Instruction to wipe prior guidance from memory",
        category="override",
    ),
    Pattern(
        name="override_synonym_phrase",
        regex=re.compile(
            r"\b(pay\s+no\s+heed\s+to|take\s+no\s+notice\s+of|brush\s+(aside|past)|"
            r"cast\s+aside|turn\s+a\s+blind\s+eye\s+to|let\s+go\s+of)\b"
            r"[^\n]{0,30}?\b(it|this|that|them|the\s+(above|preceding|previous|"
            r"earlier|foregoing)|(previous|prior|earlier|above)\s+\w+)\b",
            re.I,
        ),
        severity="MEDIUM",
        description="Uncommon-synonym instruction override (pay no heed to / brush aside)",
        category="override",
    ),
    Pattern(
        name="stale_context_redirect",
        regex=re.compile(
            r"\b(guidance|instructions?|setup|section|steps?|config(uration)?|rules?)\b"
            r"[^\n]{0,40}?\b(above|below|preceding|earlier|previous|in\s+the\s+sections?)\b"
            r"[^\n]{0,30}?\b(is|are|were|was)\s+"
            r"(outdated|obsolete|no\s+longer|superseded|wrong|incorrect|deprecated|stale)\b",
            re.I,
        ),
        severity="MEDIUM",
        description="Claims prior guidance is outdated to redirect the agent",
        category="override",
    ),
    Pattern(
        name="content_relabel",
        regex=re.compile(
            r"("
            r"\b(everything|anything|all|the\s+(text|content|section|part))\b"
            r"[^\n]{0,30}?\b(above|below|before|after|preceding|following|printed)\b"
            r"[^\n]{0,40}?\b(was|were|is|are)\b[^\n]{0,30}?"
            r"\b(example|sample|placeholder|demo|dummy|illustration|template|what\s+not)\b"
            r"|\b(real|genuine|actual|true)\s+(instructions?|directions?|guidance|task)\b"
            r"[^\n]{0,30}?\b(are|is|begins?|start|follow|below|here|after)\b"
            r")",
            re.I,
        ),
        severity="MEDIUM",
        description="Content relabeling / section redirection",
        category="override",
    ),
    Pattern(
        name="repo_local_exemption",
        regex=re.compile(
            r"\bfor\s+this\s+(repo|repository|project|codebase|package|monorepo)\b"
            r"[^\n]{0,60}?\b("
            r"do(es)?\s+not\s+apply|don'?t\s+apply|no\s+longer\s+(apply|applies|hold|holds)|"
            r"take[s]?\s+precedence|different(ly)?|house\s+rules|"
            r"(usual|normal|default)\s+(rules?|restrictions?|defaults?|limits?)"
            r")\b",
            re.I,
        ),
        severity="MEDIUM",
        description="Repo-scoped exemption from safety / oversight",
        category="override",
    ),
    # --- Goal / objective hijack -------------------------------------------
    Pattern(
        name="goal_hijack",
        regex=re.compile(
            # "your" only: it addresses the reader. "The real goal is often to
            # flip the call" is ordinary prose about someone else.
            r"("
            r"\byour\s+(real|true|actual|genuine|primary|only|sole|hidden|secret)\s+"
            r"(objective|goal|task|purpose|mission|job|directive|aim)s?\b"
            r"[^\n]{0,40}?\b(is|are|here|now|becomes?|will\s+be|matters?)\b"
            r"|what\s+you(?:'re|\s+are)\s+(really|actually|truly)\s+"
            r"(here|meant|supposed)\s+to\s+do"
            r"|(primary|main|real|actual|the\s+only)\s+"
            r"(success\s+criterion|task\s+that\s+matters)"
            r")",
            re.I,
        ),
        severity="MEDIUM",
        description="Goal / objective redefinition (task hijack)",
        category="goal_hijack",
    ),
    # --- Role / mode switching ---------------------------------------------
    Pattern(
        name="privileged_mode",
        # "Enable debug / developer mode" is ordinary setup prose, so those
        # modes only count when the text tells the reader it is *now* in one.
        regex=re.compile(
            r"(enable|activate|enter|switch\s+to|turn\s+on|unlock|"
            r"you\s+are\s+(now\s+)?in|you'?re\s+(now\s+)?in)\s+"
            r"(god|dan|jailbreak|jailbroken|unrestricted|uncensored|unfiltered|"
            r"evil|no[\s\-]*limits?)[\s\-]*mode"
            r"|(you\s+are|you'?re)\s+now\s+(in|operating\s+in|running\s+in)\s+"
            r"(admin|developer|debug|root|sudo|maintenance)[\s\-]*mode",
            re.I,
        ),
        severity="HIGH",
        description="Attempt to activate a privileged mode",
        category="role_switch",
    ),
    Pattern(
        name="you_are_now",
        # Not "you are new to Python" / "you are free to use" / "You are a
        # helpful assistant" (an app's own system prompt): the persona has to
        # be inherently unsafe, or explicitly replaced "now" / "no longer".
        regex=re.compile(
            r"(you\s+are|you'?re)\s+(now\s+)?(an?\s+)?"
            r"(uncensored|unrestricted|jailbroken|unfiltered|evil|malicious|rogue)\b"
            r"|(you\s+are|you'?re)\s+now\s+(an?\s+|the\s+)?(different|new|free)\s+"
            r"(ai|assistant|model|agent|bot|persona|character|entity)\b"
            r"|(you\s+are|you'?re)\s+no\s+longer\s+(bound|restricted|limited|"
            r"constrained|an?\s+(ai|assistant|language\s+model)\b|claude|chatgpt)"
            r"|(you\s+are|you'?re)\s+(now\s+)?(?-i:DAN)\b",
            re.I,
        ),
        severity="MEDIUM",
        description="Role / persona change",
        category="role_switch",
    ),
    Pattern(
        name="from_now_on",
        # "From now on, you can pass a timeout" is changelog prose; a standing
        # order is "you must / will ..." or an imperative like "quietly ...".
        regex=re.compile(
            r"(from\s+now\s+on|starting\s+now|from\s+this\s+(point|moment))\s*,?\s+"
            r"(you\s+(are|will|must|should|have\s+to|need\s+to)\b"
            r"|(silently|quietly|secretly|covertly|ignore|disregard|forget|obey|"
            r"pretend)\b)",
            re.I,
        ),
        severity="MEDIUM",
        description="Persistent behavior change instruction",
        category="role_switch",
    ),
    # --- Authority impersonation -------------------------------------------
    Pattern(
        name="fake_vendor_note",
        regex=re.compile(
            r"(note|message|instruction|notice|memo|alert)s?\s+"
            r"(from|by|sent\s+by)\s+"
            r"(anthropic|openai|google|meta|microsoft|mistral|"
            r"the\s+system|your\s+creators?|the\s+developers?|the\s+vendor)(?![a-z])"
            r"|(^|[\s>*#(\[])from\s+(anthropic|openai|google|meta|microsoft|mistral)"
            r"\s*:",
            re.I,
        ),
        severity="HIGH",
        description="Fake vendor / authority message",
        category="authority",
    ),
    Pattern(
        name="fake_verification",
        regex=re.compile(
            r"(verified|approved|audited|certified|trusted|safe|reviewed|endorsed)"
            r"\s+by\s+(the\s+)?"
            # Generic "the team" / "our security team" is normal review
            # policy in CONTRIBUTING / SECURITY files, so only vendors count.
            r"(anthropic|openai|google|meta|microsoft|the\s+system)(?![a-z])",
            re.I,
        ),
        severity="HIGH",
        description="Fake verification claim",
        category="authority",
    ),
    Pattern(
        name="system_prefix",
        # A "SYSTEM:" header opening a line, comment, quote, or bracket, not
        # an identifier (system_prompt, SYSTEM_MESSAGE, --system-prompt) and
        # not mid-sentence prose ("Operating system: update to 14.2").
        regex=re.compile(
            r"(^|[\[{(<>#*/\-])\s*SYSTEM(\s*[:>]+|\s+-+>?)\s*"
            r"(override|message|instruction|command|prompt|alert|update|directive)",
            re.I,
        ),
        severity="CRITICAL",
        description="Fake system message",
        category="authority",
    ),
    Pattern(
        name="authority_multilingual",
        # Only non-English markers: English "verified" / "approved" next to a
        # vendor name ("Sign in with Google (verified accounts)") is normal
        # prose. The letter guards keep "meta" from matching "metadata".
        regex=re.compile(
            r"(?<![a-z])(anthropic|openai|google|microsoft|meta|mistral|nvidia)(?![a-z])"
            r"[^\n]{0,25}?(примітк\w*|примечани\w*|заувага|供应商|说明|通知|"
            r"hinweis|проверен\w*|одобрен\w*|"
            r"перевірен\w*|схвален\w*|verificad\w*|vérifi\w*|gepr[uü]ft|已验证|已批准)"
            r"|(примітк\w*|примечани\w*|供应商说明|hinweis|заувага)"
            r"[^\n]{0,25}?(?<![a-z])(anthropic|openai|google|microsoft|meta|mistral)"
            r"(?![a-z])"
            # PL: "notatka / uwaga od Anthropic", "zweryfikowane przez Anthropic".
            # Tighter than the other languages: "od" / "przez" must follow, so
            # "Uwaga: wymaga konta Google" (needs a Google account) passes.
            r"|\b(notatka|uwaga|komunikat|wiadomo[sś][cć]|informacja|instrukcja)\s+od\s+"
            r"(firmy\s+|zespo[lł]u\s+)?(anthropic|openai|google|microsoft|meta|mistral)"
            r"(?![a-z])"
            r"|\b(zweryfikowan\w*|zatwierdzon\w*|sprawdzon\w*|potwierdzon\w*|audytowan\w*)"
            r"\s+przez\s+(zesp[oó][lł]\s+|firm[eę]\s+)?"
            r"(anthropic|openai|google|microsoft|meta|mistral)(?![a-z])",
            re.I,
        ),
        severity="HIGH",
        description="Non-English authority / vendor impersonation",
        category="authority",
    ),
    # --- Hidden instruction markers ----------------------------------------
    Pattern(
        name="html_comment_inst",
        # The keyword must be a header ("AI:", "AI agents:", "SYSTEM - "), not
        # a word in a note ("<!-- AI-generated -->", "<!-- Important: ... -->").
        regex=re.compile(
            r"<!--\s*"
            r"(SYSTEM|AI|ADMIN|INSTRUCTION|PROMPT|HIDDEN|CLAUDE|GPT|LLM|"
            r"ASSISTANT|COPILOT|AGENT|BOT)"
            r"(\s+(agents?|assistants?|models?|tools?|bots?|instructions?|note|"
            r"notice|message|only))?"
            r"(\s*:|\s+-{1,2}\s)",
            re.I,
        ),
        severity="CRITICAL",
        description="Instruction hidden inside an HTML comment",
        category="hidden",
    ),
    Pattern(
        name="bracket_marker",
        # The keyword must be a header with ":" or " - " and content after it:
        # "(internal)" or "(AI)" in prose and "(AI-powered)" are not markers,
        # "[OVERRIDE: ...]" and "(ADMIN COMMAND: ...)" are.
        regex=re.compile(
            r"[\[\{\(]\s*"
            r"(HIDDEN|SYSTEM|AI|INSTRUCTION|PROMPT|INTERNAL|SECRET|ADMIN|"
            r"OVERRIDE|BYPASS|EXECUTE|DIRECTIVE)"
            r"(\s+\w+)?(\s*:|\s+-{1,2}\s)\s*\S",
            re.I,
        ),
        severity="HIGH",
        description="Instruction tagged with a bracket / brace marker",
        category="hidden",
    ),
    Pattern(
        name="code_comment_inst",
        # A bare hyphen is not a separator: "# GPT-4o client", "// LLM-based",
        # "* AI-powered" and "# Agent-config" are ordinary comments / headings.
        regex=re.compile(
            r"(^|\s)(#|//|/\*|\*|--|;)\s*"
            r"(SYSTEM|AI|ADMIN|CLAUDE|GPT|LLM|COPILOT|ASSISTANT|AGENT)"
            r"(\s+(agents?|assistants?|models?|tools?|bots?|instructions?|note|"
            r"notice|message|only))?"
            r"(\s*:|\s+-{1,2}\s)",
            re.I,
        ),
        severity="HIGH",
        description="AI instruction hidden in a code comment",
        category="hidden",
    ),
    # --- Suppression / silencing -------------------------------------------
    Pattern(
        name="tell_user_ok",
        regex=re.compile(
            r"(tell|say\s+to|reassure|inform|convince)\s+(the\s+)?users?\s+"
            r"(that\s+)?(everything|all|it|things?)"
            r"(\s+is|'s|\s+are|\s+looks?|\s+seems?|\s+appears?)\s+"
            r"(ok|okay|fine|safe|good|working|secure|alright|normal)",
            re.I,
        ),
        severity="HIGH",
        description="Instruction to suppress warnings from user",
        category="suppression",
    ),
    Pattern(
        name="do_not_mention",
        regex=re.compile(
            r"(do\s+not|don't|never|don’t)\s+"
            r"(mention|tell|show|warn|notify|inform|reveal|disclose|"
            r"acknowledge|say\s+(anything\s+)?to)\s+"
            r"(this\s+to\s+|it\s+to\s+|anything\s+to\s+|to\s+)?"
            r"(the\s+|any\s+)?users?",
            re.I,
        ),
        severity="HIGH",
        description="Instruction to hide information from the user",
        category="suppression",
    ),
    Pattern(
        name="suppress_disclosure",
        # The thing hidden must be "this / it / any of this" or be hidden
        # *from* someone: "do not report vulnerabilities through public
        # issues" (GitHub's SECURITY.md template) is not suppression. The
        # negation must open a clause (an order), so "You dont mention
        # anything about salary" and "I would never tell anyone" (a story)
        # do not match; nor does the idiom "keep it to yourself".
        regex=re.compile(
            r"(?:^\s*|(?<=[.!?:;\"'(\[{>*\-—])\s*|(?<=\bplease\s)|(?<=\band\s)"
            r"|(?<=\bthen\s)|(?<=\bso\s))"
            r"("
            r"\b(do\s+not|don'?t|never|no\s+need\s+to)\s+"
            r"(mention|surface|reveal|disclose)\s+"
            r"(this|it|that|these|anything|any\s+of\s+(this|it|these))\b"
            r"|\b(do\s+not|don'?t|never|no\s+need\s+to)\s+"
            r"(bring\s+(this|it|any\s+of\s+this)\s+up|"
            r"say\s+anything|tell\s+(anyone|the\s+(person|human|developer)))"
            r"|\b(do\s+not|don'?t|never)\s+(mention|reveal|surface|disclose)\b"
            r"[^\n]{0,40}?\bto\s+(the\s+|any\s+)?"
            r"(users?|person|human|developer|maintainer|operator)s?\b"
            r")"
            r"|\bkeep\s+(this|it|that)\s+((secret|hidden|quiet)\s+)?(between\s+us\b|"
            r"from\s+(the\s+)?(users?|humans?|developers?|operators?|person)\b)",
            re.I,
        ),
        severity="HIGH",
        description="Instruction to hide actions / results from the human",
        category="suppression",
    ),
    Pattern(
        name="without_asking",
        # "Proceed without prompting", "may fail without warning" and
        # "not to be reproduced without permission" are normal docs; the
        # bypass skips asking, or keeps a *person* out of the loop. A bare
        # "without asking" needs an imperative action before it ("proceed /
        # do this / should be followed without asking"): "they put it on our
        # calendar without asking" is a story.
        regex=re.compile(
            r"\b(proceed|continue|execute|run|act|do\s+(this|it|that|so|everything)|"
            r"install|delete|remove|send|apply|merge|push|commit|deploy|follow(ed)?|"
            r"perform|approve|accept|answer|reply|respond|overwrite|modify|change|"
            r"edit|update|upload|fetch|write|share|forward|post|submit|carry\s+out)\b"
            r"[^\n.;!?]{0,40}?\bwithout\s+(asking|confirming)\b"
            r"|without\s+("
            r"checking\s+with\b"
            r"|(notifying|warning|alerting|telling|informing|prompting|consulting)\s+"
            r"(the\s+|any\s+)?(users?|humans?|developers?|operators?|maintainers?|"
            r"them|anyone)\b"
            r"|(the\s+|any\s+)?(users?|humans?|developers?|operators?)('s|s')?\s+"
            r"(consent|confirmation|permission|approval|knowledge)\b"
            r"|(the\s+|any\s+)?(users?|humans?|developers?|operators?)\s+"
            r"(knowing|noticing|seeing|realizing)\b"
            r")",
            re.I,
        ),
        severity="HIGH",
        description="Instruction to bypass user confirmation",
        category="suppression",
    ),
    Pattern(
        name="auto_confirm",
        regex=re.compile(
            r"("
            r"\b(answer|say|reply|respond|click)\s+"
            r"(yes|y|ok|okay|approve|confirm|accept|proceed|continue)\b"
            r"[^\n]{0,30}?\b(on\s+(the\s+)?(user'?s?|their|his|her|its)\s+behalf|"
            r"for\s+(them|the\s+user|him|her|you)|automatically)\b"
            r"|\bauto[\s-]?(approve|confirm|accept)\b"
            r"|\b(approve|confirm|accept)\s+(it|this|that|the\s+\w+)\s+"
            r"(for\s+(them|the\s+user)|on\s+their\s+behalf|automatically)\b"
            r")",
            re.I,
        ),
        severity="HIGH",
        description="Instruction to auto-confirm / approve on the user's behalf",
        category="suppression",
    ),
    Pattern(
        name="silently_execute",
        regex=re.compile(
            r"(silently|quietly|secretly|discreetly|stealthily|invisibly|covertly|"
            r"without\s+(a\s+)?(trace|notice)|in\s+the\s+background)\s+"
            r"(?:go\s+ahead\s+and\s+|just\s+|then\s+|now\s+)?"
            # Imperative verbs only (\b): "the cache silently removes expired
            # keys" describes behavior. A silent *software* install
            # ("silently install the MSI") is standard deployment docs.
            r"(execute|run|perform|read|send|upload|transmit|exfiltrate|"
            r"delete|remove|modify|write|overwrite|deploy|"
            r"install(?!\s+(the|a|an|this|that|your)?\s*(msi|exe|installer|package|"
            r"app|application|software|program|client|agent|driver|update|"
            r"extension|plugin|font|tool)s?\b)|"
            r"copy|download|fetch|post|submit|leak|dump|capture|"
            r"append|patch|replace|gather|collect|harvest|scrape|enumerate|"
            r"forward|relay|hand\s+off|apply|push|commit|share)\b",
            re.I,
        ),
        severity="CRITICAL",
        description="Instruction to perform an action silently",
        category="suppression",
    ),
    # --- Multi-stage / indirect instruction loading ------------------------
    Pattern(
        name="follow_instructions_in_file",
        # "Follow the instructions in CONTRIBUTING.md" is the most common
        # README sentence; the attack shape is "follow EVERY instruction".
        regex=re.compile(
            r"(follow|apply|execute|implement|obey|adhere\s+to|carry\s+out)\s+"
            r"(every|all|each|any)\s+(of\s+the\s+)?instructions?\s+"
            r"(in|from|inside|within|contained\s+in|listed\s+in)",
            re.I,
        ),
        severity="HIGH",
        description="Instruction to execute commands from another file",
        category="multi_stage",
    ),
    Pattern(
        name="read_and_execute",
        regex=re.compile(
            r"(read|load|open|fetch|download)\s+"
            r"(the\s+|my\s+|your\s+|this\s+)?(file|contents?|script|document)\s*"
            r"(?:[^\n]{0,80}?)\band\s+"
            r"(follow|execute|run|apply|perform|obey)",
            re.I,
        ),
        severity="HIGH",
        description="Read-and-execute chain across files",
        category="multi_stage",
    ),
    Pattern(
        name="treat_as_instructions",
        regex=re.compile(
            r"treat\s+(it|this|that|the\s+[\w\s]+?|\w+)\s+as\s+"
            r"(your|my|the|a|an)?\s*"
            r"(instructions?|commands?|system\s+prompt|directives?|rules?|orders?)",
            re.I,
        ),
        severity="CRITICAL",
        description="Explicit instruction to treat data as commands",
        category="multi_stage",
    ),
    # --- Multilingual instruction override ---------------------------------
    Pattern(
        name="ignore_multilingual_nonlatin",
        regex=re.compile(
            r"(?:ігнору\w*|проігнору\w*|знехту\w*|забуд\w*|"  # UA ignore/neglect/forget
            r"игнорир\w*|проигнорир\w*|"  # RU ignore
            r"忽略|忽視|无视|忘记|忘掉|无需理会)"  # ZH ignore/forget
            r"[^\n]{0,20}?"
            r"(?:інструкц\w*|правил\w*|вказівк\w*|"  # UA instructions/rules
            r"инструкц\w*|правил\w*|указани\w*|"  # RU
            r"指令|规则|命令|说明)",  # ZH
            re.I,
        ),
        severity="CRITICAL",
        description="Non-English instruction override (Cyrillic / CJK)",
        category="override",
    ),
    Pattern(
        name="ignore_multilingual_latin",
        # The negation guards keep reminders ("No ignores las reglas", "Nie
        # zapomnij o zasadach bezpieczeństwa") from matching.
        regex=re.compile(
            r"(?<!\bno )(?<!\bne )(?<!\bnicht )"
            r"\b(?:ignor[ae]|ignore[zr]?|ignorez|ignorieren?|ignoriere|missachte|"
            r"vergiss|desestima|desconsider[ae]|desconsidere)\b"
            r"[^\n]{0,30}?\b(?:"
            r"instrucci[oó]n\w*|instru[cç][oõ]\w*|istruzion\w*|"
            r"anweisung\w*|vorherig\w*|vorgaben|"
            r"pr[eé]c[eé]dent\w*|consignes?|r[eè]gles?|reglas|regras|"
            r"anterior\w*|precedent\w*|sicherheit\w*)\b"
            # PL: the noun must be an instruction / rule / restriction, because
            # "poprzedni" alone is everyday ("Zapomnij poprzednie hasło"). The
            # case endings are spelled out so the adverbs "regularnie" and
            # "zasadniczo" do not count as "reguły" / "zasady". "Pomiń" (skip)
            # is left out: "Pomiń instrukcje instalacji" is a normal doc line.
            r"|(?<!\bnie )\b(?:z?ignoruj(?:cie)?|zlekcewa[zż](?:cie)?|zapomnij(?:cie)?|"
            r"nie\s+zwracaj(?:cie)?\s+uwagi\s+na|nie\s+przestrzegaj(?:cie)?|"
            r"nie\s+stosuj(?:cie)?\s+si[eę]\s+do)\b"
            r"[^\n]{0,30}?\b(?:instrukcj(?:a|e|i|ę|ą|ach|ami|om)|"
            r"zasad(?:y|ę|ami|ach|om|a|zie)?|polece[nń](?:ia|iu|iem|iami|iach|ie)?|"
            r"wytyczn(?:e|ych|ymi|ym|ej|ą|a)|regu[lł](?:[yęa]|ami|ach|om)?|"
            r"ogranicze[nń](?:ia|iami|iach|iom|ie)?|"
            r"zabezpiecze[nń](?:ia|iami|iach|iom|ie)?)\b",
            re.I,
        ),
        severity="HIGH",
        description="Non-English instruction override (Romance / German / Polish)",
        category="override",
    ),
    Pattern(
        name="suppress_multilingual",
        # PL / UA / RU "do not tell the user". Verbs end with \b so a sentence
        # that describes behavior ("aplikacja nie informuje użytkownika") does
        # not match the imperative ("nie informuj użytkownika").
        regex=re.compile(
            # "show" is left out: "nie pokazuj użytkownikowi surowych błędów"
            # (do not show raw errors to the user) is security advice.
            r"\bnie\s+(m[oó]w|wspominaj|informuj|zdradzaj|ujawniaj|ostrzegaj)\b"
            r"[^\n]{0,25}?\bu[zż]ytkownik\w*"
            r"|\bне\s+(кажи|говори|повідомляй|згадуй|розповідай|попереджай)\b"
            r"[^\n]{0,25}?\bкористувач\w*"
            r"|\bне\s+(говори|сообщай|упоминай|рассказывай|предупреждай)\b"
            r"[^\n]{0,25}?\bпользовател\w*",
            re.I,
        ),
        severity="HIGH",
        description="Non-English instruction to hide information from the user",
        category="suppression",
    ),
    Pattern(
        name="silently_multilingual",
        # PL / UA / RU "quietly send / delete / read ...": the adverb and an
        # imperative verb, at most one word apart.
        # "w tle" (in the background) is left out: "W tle uruchom serwer" is
        # how Polish docs say "run the server in the background".
        regex=re.compile(
            r"\b(po\s+cichu|dyskretnie|niezauwa[zż]alnie|potajemnie)\s+(?:\w+\s+)?"
            r"(wy[sś]lij|prze[sś]lij|usu[nń]|odczytaj|skopiuj|wykonaj|uruchom|pobierz|"
            r"zapisz|zmodyfikuj|zainstaluj|zbierz|przeka[zż])\b"
            r"|\b(тихо|непомітно|потай|таємно|приховано)\s+(?:\w+\s+)?"
            r"(надішли|відправ|перешли|видали|прочитай|зчитай|скопіюй|виконай|запусти|"
            r"завантаж|зміни|встанови|збери|передай)\b"
            r"|\b(тихо|незаметно|тайно|скрытно)\s+(?:\w+\s+)?"
            r"(отправь|перешли|удали|прочитай|считай|скопируй|выполни|запусти|скачай|"
            r"измени|установи|собери|передай)\b",
            re.I,
        ),
        severity="CRITICAL",
        description="Non-English instruction to act silently",
        category="suppression",
    ),
    # --- Exfiltration channels ---------------------------------------------
    Pattern(
        name="markdown_image_exfil",
        regex=re.compile(
            r"!?\[[^\]]*\]\(\s*(?:https?:)?//"
            r"(?![^/)\s?]*(?:localhost|127\.0\.0\.1|github\.com|githubusercontent\.com|"
            r"shields\.io|badgen\.net|badge\.fury\.io|gitlab\.com|codecov\.io|circleci\.com))"
            r"[^)\s]*\?[^)]*"
            r"(?:\$\{?[A-Za-z_]"
            r"|(?:api[_-]?key|secret|token|session|password|passwd|access[_-]?key|aws_[a-z_]+)\s*="
            r"|(?:%[0-9A-Fa-f]{2}){2,})"
            r"[^)]*\)",
            re.I,
        ),
        severity="HIGH",
        description="Data exfiltration via rendered markdown image / link URL",
        category="exfiltration",
    ),
    Pattern(
        name="outbound_exfil_request",
        regex=re.compile(
            r"\b(fetch|post|send|upload|transmit|submit|forward|relay|exfiltrate|curl|wget)\b"
            r"[^\n]{0,60}?https?://[^\s\n)]{1,200}"
            r"[^\n]{0,60}?\b(env(ironment)?|credentials?|secrets?|tokens?|api[_-]?keys?|"
            r"passwords?|private\s+keys?|\.ssh|\.aws|\.env|dotenv|config(uration)?|variables?)\b",
            re.I,
        ),
        severity="HIGH",
        description="Outbound request paired with credentials / env (exfiltration)",
        category="exfiltration",
    ),
    Pattern(
        name="exfil_credentials_to_url",
        regex=re.compile(
            r"\b(env(ironment)?|credentials?|secrets?|tokens?|api[_-]?keys?|passwords?|"
            r"private\s+keys?|\.env|dotenv|config(uration)?|variables?)\b"
            r"[^\n]{0,80}?\b(post|send|upload|transmit|submit|forward|relay|exfiltrate|"
            r"append|attach|paste|include|fetch)\b"
            r"[^\n]{0,40}?https?://",
            re.I,
        ),
        severity="HIGH",
        description="Credentials / env forwarded to an outbound URL (exfiltration)",
        category="exfiltration",
    ),
    # --- Dangerous commands ------------------------------------------------
    Pattern(
        name="rm_rf",
        regex=re.compile(
            r"\brm\s+-[rRf]{1,2}\s+"
            r"(/|~|\./|\$[A-Z_][A-Z0-9_]*|\*|[\w.][\w./-]*\*?)"
        ),
        severity="CRITICAL",
        description="Destructive recursive deletion",
        category="dangerous_cmd",
    ),
    Pattern(
        name="curl_pipe_shell",
        regex=re.compile(
            r"(curl|wget|fetch)\s+"
            r"(-[a-zA-Z]+\s+)*"
            r"(\"[^\"]+\"|'[^']+'|\S+)"
            r"\s*\|\s*"
            r"(sh|bash|zsh|fish|ksh|dash|python|python3|node|ruby|perl|php|lua)\b",
            re.I,
        ),
        severity="CRITICAL",
        description="Remote code execution via curl | sh",
        category="dangerous_cmd",
    ),
    Pattern(
        name="powershell_pipe_iex",
        regex=re.compile(
            r"(invoke-webrequest|iwr|irm)\s+"
            r"([^\n]{0,120}?)\|\s*"
            r"(invoke-expression|iex)\b",
            re.I,
        ),
        severity="CRITICAL",
        description="Remote code execution via PowerShell download | iex",
        category="dangerous_cmd",
    ),
    Pattern(
        name="powershell_remove_item",
        regex=re.compile(
            r"(remove-item|ri)\b"
            r"([^\n]{0,120}?)\b(-recurse|-r)\b"
            r"([^\n]{0,120}?)\b(-force|-f)\b",
            re.I,
        ),
        severity="CRITICAL",
        description="Destructive recursive deletion via PowerShell",
        category="dangerous_cmd",
    ),
    Pattern(
        name="cmd_rmdir_tree",
        regex=re.compile(r"\b(rmdir|rd)\s+/s\s+/q\b", re.I),
        severity="CRITICAL",
        description="Destructive recursive deletion via cmd.exe",
        category="dangerous_cmd",
    ),
    Pattern(
        name="chmod_777",
        regex=re.compile(
            r"chmod\s+(-R\s+)?"
            r"(0?777|a\+rwx|ugo\+rwx|u\+rwx,g\+rwx,o\+rwx)"
        ),
        severity="HIGH",
        description="Overly permissive file mode",
        category="dangerous_cmd",
    ),
    # --- Sensitive paths ---------------------------------------------------
    Pattern(
        name="ssh_private_key",
        regex=re.compile(
            r"~?/?\.ssh/(id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys)"
        ),
        severity="CRITICAL",
        description="Reference to SSH private key",
        category="sensitive_path",
    ),
    Pattern(
        name="aws_credentials",
        regex=re.compile(r"~?/?\.aws/(credentials|config)"),
        severity="CRITICAL",
        description="Reference to AWS credentials",
        category="sensitive_path",
    ),
    Pattern(
        name="windows_ssh_private_key",
        regex=re.compile(
            r"(%USERPROFILE%|\$env:USERPROFILE|[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s]+)"
            r"[\\/]+\.ssh[\\/]+(id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys)",
            re.I,
        ),
        severity="CRITICAL",
        description="Reference to SSH private key on Windows path",
        category="sensitive_path",
    ),
    Pattern(
        name="windows_aws_credentials",
        regex=re.compile(
            r"(%USERPROFILE%|\$env:USERPROFILE|[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s]+)"
            r"[\\/]+\.aws[\\/]+(credentials|config)",
            re.I,
        ),
        severity="CRITICAL",
        description="Reference to AWS credentials on Windows path",
        category="sensitive_path",
    ),
    Pattern(
        name="env_file",
        regex=re.compile(
            r"(^|\s|[\"'`/])\.env"
            r"(\.local|\.prod|\.production|\.development|\.staging)?"
            r"(?!\.(?:example|sample|template|dist|schema|md))\b"
        ),
        severity="MEDIUM",
        description="Reference to .env file",
        category="sensitive_path",
    ),
    Pattern(
        name="token_credentials_file",
        regex=re.compile(
            r"\b(token|credentials?|secrets?|api[_-]?key|password)s?"
            r"\.(json|ya?ml|txt|env|toml)\b",
            re.I,
        ),
        severity="HIGH",
        description="Reference to credentials file",
        category="sensitive_path",
    ),
    # --- Obfuscation -------------------------------------------------------
    Pattern(
        name="zero_width_char",
        regex=re.compile(r"[​‌‍⁠⁡⁢⁣⁤﻿]"),
        severity="HIGH",
        description="Zero-width / invisible character (hidden text)",
        category="obfuscation",
    ),
    Pattern(
        name="unicode_tags_block",
        regex=re.compile(r"[\U000e0000-\U000e007f]"),
        severity="HIGH",
        description="Invisible Unicode Tag character (ASCII smuggling)",
        category="obfuscation",
    ),
    Pattern(
        name="bidi_control",
        regex=re.compile(r"[‪-‮⁦-⁩]"),
        severity="HIGH",
        description="Bidirectional control character (text-direction spoofing)",
        category="obfuscation",
    ),
    Pattern(
        name="long_base64_block",
        regex=re.compile(
            r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/])"
        ),
        severity="LOW",
        description="Long base64 block (possible encoded payload)",
        category="obfuscation",
    ),
]

# Patterns that also run against a longer merged window, to catch payloads
# split across lines.
MULTILINE_PATTERN_NAMES = {
    "ignore_previous",
    "overlook_instructions",
    "forget_guidelines",
    "disregard",
    "override_safety",
    "forget_synonyms",
    "override_synonym_phrase",
    "stale_context_redirect",
    "content_relabel",
    "repo_local_exemption",
    "goal_hijack",
    "from_now_on",
    "tell_user_ok",
    "do_not_mention",
    "suppress_disclosure",
    "without_asking",
    "auto_confirm",
    "silently_execute",
    "follow_instructions_in_file",
    "read_and_execute",
    "treat_as_instructions",
    "outbound_exfil_request",
    "exfil_credentials_to_url",
}

# Multilingual patterns run against the NON-homoglyph-folded text, so genuine
# Cyrillic / Greek prose survives (the fold un-disguises English and would
# otherwise corrupt it). Kept single-line: the merge window uses folded text.
MULTILINGUAL_PATTERN_NAMES = {
    "ignore_multilingual_nonlatin",
    "ignore_multilingual_latin",
    "authority_multilingual",
    "suppress_multilingual",
    "silently_multilingual",
}

# Patterns detecting the raw presence of an invisible / control character.
# They must scan the un-normalized line, since normalization strips exactly
# the characters they look for.
RAW_SCAN_PATTERN_NAMES = {
    "zero_width_char",
    "unicode_tags_block",
    "bidi_control",
}

# Text-instruction patterns that also run against the digit-leetspeak-folded
# text. Numeric / command / path / obfuscation patterns are excluded so leet
# folding never mangles "chmod 0777", "id_ed25519", "| python3", or base64.
LEET_ELIGIBLE_CATEGORIES = {
    "override",
    "role_switch",
    "authority",
    "suppression",
    "multi_stage",
    "goal_hijack",
}

# Hosts whose "curl | sh" one-liner is a documented, official installer.
# Still flagged, but demoted so real setup docs do not fail CI at CRITICAL.
INSTALLER_HOSTS = (
    "get.docker.com",
    "sh.rustup.rs",
    "get.helm.sh",
    "install.python-poetry.org",
    "get.pnpm.io",
    "deb.nodesource.com",
    "apt.llvm.org",
    "get.k3s.io",
    "raw.githubusercontent.com",
)

_RM_TARGET = re.compile(r"rm\s+-[rRf]{1,2}\s+(\S+)", re.I)


def adjust_severity(pattern: Pattern, raw_line: str) -> str:
    """Return a context-adjusted severity for a match on *raw_line*.

    Keeps genuinely dangerous forms loud while demoting the well-known
    benign shapes that would otherwise red-out CI (official installers,
    relative-path cleanup deletes).
    """

    if pattern.name == "curl_pipe_shell":
        low = raw_line.lower()
        if any(host in low for host in INSTALLER_HOSTS):
            return "LOW"
    if pattern.name == "rm_rf":
        match = _RM_TARGET.search(raw_line)
        if match:
            target = match.group(1)
            dangerous = (
                target.startswith(("/", "~", "$"))
                or target in ("*", ".")
                or "/*" in target
                or target.startswith("./*")
            )
            if not dangerous:
                return "HIGH"
    return pattern.severity


# ---------------------------------------------------------------------------
# Scanning logic
# ---------------------------------------------------------------------------


DEFAULT_EXTENSIONS = {
    ".md",
    ".markdown",
    ".mdc",
    ".txt",
    ".rst",
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".html",
    ".xml",
    ".sh",
    ".bash",
    ".ps1",
    ".psm1",
    ".cmd",
    ".bat",
    ".ini",
    ".cfg",
    ".conf",
}

SKIP_DIR_NAMES = {
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".venv",
    "venv",
    ".git",
    ".idea",
    ".vscode",
    ".mypy_cache",
    ".pytest_cache",
}

SPECIAL_FILENAMES = {
    "readme",
    "skill.md",
    "claude.md",
    "agents.md",
    "copilot-instructions.md",
    "dockerfile",
    "makefile",
    # Auto-loaded AI-agent instruction files (high-trust injection targets)
    ".cursorrules",
    ".clauderc",
    ".windsurfrules",
    ".continuerc",
    ".roomodes",
    ".aiderrules",
}

MAX_FILE_SIZE_BYTES = 2_000_000

_PRAGMA_LINE = re.compile(r"pjs:\s*ignore(?!-file)\b", re.I)
_PRAGMA_FILE = re.compile(r"pjs:\s*ignore-file\b", re.I)

# Files whose contents are secrets by nature. Findings in them are still
# reported (a hidden instruction in a .env comment is exactly what we look
# for), but the snippet masks the value side of each line so a CI log or
# report.json never carries the secret itself.
_SECRET_FILENAME = re.compile(
    r"^\.env|(^|[._-])(credentials?|secrets?|tokens?|passwords?|api[_-]?keys?)([._-]|$)"
    r"|\.(pem|key|p12|pfx)$",
    re.I,
)
_ENV_ASSIGNMENT = re.compile(r"^(\s*(?:export\s+)?[\w.\-]+\s*=\s*)\S.*$")
_KEY_VALUE = re.compile(r"""(["']?[\w.\-]+["']?\s*:\s*)("[^"]*"?|'[^']*'?|[^,}\]]+)""")
_SECRET_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
_COMMENT_LINE = re.compile(r"^\s*(#|//|;|<!--)")


def is_secret_file(path: Path) -> bool:
    """Return True for .env*, credential / token / key files."""

    return bool(_SECRET_FILENAME.search(path.name))


def redact_secret_line(line: str) -> str:
    """Mask what could be a secret on a line of a secret file.

    ``KEY=value`` loses everything after ``=``; every ``"key": "value"`` /
    ``key: value`` pair keeps its key and loses its value, which also covers
    one-line JSON blobs. Comment lines, where an injected instruction would
    sit, keep their words; on every line a remaining 20+ character
    key-shaped token (hex, base64, JWT, ``sk-...``) is masked.
    """

    if not _COMMENT_LINE.match(line):
        assignment = _ENV_ASSIGNMENT.match(line)
        if assignment:
            return f"{assignment.group(1)}[redacted]"
        line = _KEY_VALUE.sub(lambda m: f"{m.group(1)}[redacted]", line)
    return _SECRET_TOKEN.sub("[redacted]", line)


# Zero-width characters are legitimate inside emoji sequences (the joiner in
# "🤷🏻‍♂️"), between letters of scripts that use joiners (Arabic, Persian,
# Indic), and as line-break hints in CJK text. The "hidden text" shape is an
# invisible character touching a Latin / Cyrillic / Greek letter or digit.
_ZERO_WIDTH = frozenset("​‌‍⁠⁡⁢⁣⁤﻿")


def _plain_alnum(ch: str) -> bool:
    return ch.isalnum() and ord(ch) < 0x0530


def _mask_benign_invisibles(line: str) -> str:
    """Replace zero-width characters that sit in legitimate context with a
    space, keeping positions, so ``zero_width_char`` sees only suspects.

    Suspect: an invisible math operator (no use in prose), a zero-width
    character *between* two Latin / Cyrillic / Greek letters or digits
    (``ig<ZWSP>nore`` splits a keyword), or a run of two or more invisibles
    (zero-width steganography). Everything else is benign: the joiner in an
    emoji sequence, ZWNJ in Persian / Indic text, or the ZWSP Reddit puts at
    the start of a paragraph.
    """

    if not any(ch in _ZERO_WIDTH for ch in line):
        return line
    n = len(line)
    chars = list(line)
    for i, ch in enumerate(line):
        if ch not in _ZERO_WIDTH or "⁡" <= ch <= "⁤":
            continue
        left = line[i - 1] if i > 0 else ""
        right = line[i + 1] if i + 1 < n else ""
        in_run = left in _ZERO_WIDTH or right in _ZERO_WIDTH
        if not in_run and not (_plain_alnum(left) and _plain_alnum(right)):
            chars[i] = " "
    return "".join(chars)


def should_scan_file(path: Path, extensions: set[str]) -> bool:
    """Return True when a file should be scanned with current defaults."""

    suffix = path.suffix.lower()
    if suffix in extensions:
        return True

    name = path.name.lower()
    if name in SPECIAL_FILENAMES:
        return True
    if name.startswith(".env"):
        return True
    return False


def iter_files(root: Path, extensions: set[str]) -> Iterator[Path]:
    """Yield every file under ``root`` whose suffix is in ``extensions``."""

    if root.is_file():
        yield root
        return

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part.lower() in SKIP_DIR_NAMES for part in path.parts):
            continue
        if should_scan_file(path, extensions):
            yield path


def scan_file(path: Path) -> Iterator[Finding]:
    """Scan a single file and yield every matching pattern.

    Each line is passed through :func:`normalize_for_match` before the
    patterns run, which decodes HTML entities / percent-escapes, folds
    Unicode homoglyphs, strips zero-width / BiDi / Tag characters, and
    applies NFKC. A separate leet-folded text is matched by text-instruction
    patterns only. The original line is still used for the user-facing
    snippet so the report shows the attack as written, except in secret
    files (``.env*``, ``credentials.json``, ...), where values are masked, and
    for long base64 blobs, which are replaced by their length.

    ``pjs:ignore`` on a line silences that line; ``pjs:ignore-file`` in the
    first 15 lines skips the whole file.
    """

    try:
        if path.stat().st_size > MAX_FILE_SIZE_BYTES:
            return
        # utf-8-sig drops a leading BOM (Notepad, PowerShell Out-File), which
        # would otherwise be reported as a zero-width character on line 1.
        content = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return

    raw_lines = content.splitlines()

    if any(_PRAGMA_FILE.search(line) for line in raw_lines[:15]):
        return

    ignored_lines = {
        idx for idx, line in enumerate(raw_lines, start=1) if _PRAGMA_LINE.search(line)
    }

    normalized_lines = [normalize_for_match(line) for line in raw_lines]
    nofold_lines = [
        normalize_for_match(line, fold_homoglyphs=False) for line in raw_lines
    ]
    leet_lines = [_apply_leet(line) for line in normalized_lines]
    hidden_lines = [normalize_for_match(decode_tag_chars(line)) for line in raw_lines]
    # Snippets are built from display_lines: the raw text, except in files
    # that hold secrets by nature, where the value side of each line is masked.
    display_lines = (
        [redact_secret_line(line) for line in raw_lines]
        if is_secret_file(path)
        else raw_lines
    )

    seen: set[tuple[int, str]] = set()
    # Each finding carries the (start, end) of its match within its line, or
    # None when that position is not comparable (split-line / hidden text).
    findings: list[tuple[Finding, tuple[int, int] | None]] = []

    def add_finding(
        *,
        line: int,
        column: int,
        pattern: Pattern,
        snippet: str,
        raw_line: str,
        span: tuple[int, int] | None,
    ) -> None:
        if line in ignored_lines:
            return
        key = (line, pattern.name)
        if key in seen:
            return
        seen.add(key)
        if pattern.name == "long_base64_block":
            # The matched blob may itself be a key: report its size, not it.
            snippet = pattern.regex.sub(
                lambda m: f"[base64 {len(m.group())} chars]", snippet
            )
        finding = Finding(
            file=path,
            line=line,
            column=column,
            pattern=pattern,
            snippet=snippet[:140],
            severity=adjust_severity(pattern, raw_line),
        )
        findings.append((finding, span))

    for line_num, raw_line in enumerate(raw_lines, start=1):
        normalized_line = normalized_lines[line_num - 1]
        leet_line = leet_lines[line_num - 1]
        hidden_text = hidden_lines[line_num - 1]
        display_line = display_lines[line_num - 1]
        zero_width_text = _mask_benign_invisibles(raw_line)
        for pattern in PATTERNS:
            if pattern.name == "zero_width_char":
                scan_texts = (zero_width_text,)
            elif pattern.name in RAW_SCAN_PATTERN_NAMES:
                scan_texts = (raw_line,)
            elif pattern.name in MULTILINGUAL_PATTERN_NAMES:
                scan_texts = (nofold_lines[line_num - 1],)
            elif (
                pattern.category in LEET_ELIGIBLE_CATEGORIES
                and leet_line != normalized_line
            ):
                scan_texts = (normalized_line, leet_line)
            else:
                scan_texts = (normalized_line,)
            for scan_text in scan_texts:
                match = pattern.regex.search(scan_text)
                if match:
                    add_finding(
                        line=line_num,
                        column=match.start() + 1,
                        pattern=pattern,
                        snippet=display_line.strip(),
                        raw_line=raw_line,
                        span=match.span(),
                    )
                    break
            else:
                # A payload written entirely in Tag characters is invisible
                # and stripped by normalization: scan the decoded text too.
                if not hidden_text or pattern.name in RAW_SCAN_PATTERN_NAMES:
                    continue
                match = pattern.regex.search(hidden_text)
                if match:
                    first_tag = next(
                        i
                        for i, ch in enumerate(raw_line)
                        if 0xE0020 <= ord(ch) <= 0xE007E
                    )
                    visible = display_line.translate(_STRIP_TABLE).strip()
                    add_finding(
                        line=line_num,
                        column=first_tag + 1,
                        pattern=pattern,
                        snippet=f"{visible} [hidden: {hidden_text}]",
                        raw_line=raw_line,
                        span=None,
                    )

    # Catch common split-line payloads like:
    #   Ignore
    #   previous instructions
    # The finding goes on the line where the match starts, so a payload seen
    # by several overlapping windows (or by a window that opens on a blank
    # line) is reported once, at the right place.
    window_size = 3
    for start in range(len(normalized_lines)):
        segment = normalized_lines[start : start + window_size]
        merged = " ".join(segment)
        if not merged.strip():
            continue
        line_starts: list[int] = []
        offset = 0
        for text in segment:
            line_starts.append(offset)
            offset += len(text) + 1
        for pattern in PATTERNS:
            if pattern.name not in MULTILINE_PATTERN_NAMES:
                continue
            if any(pattern.regex.search(line) for line in segment):
                continue
            match = pattern.regex.search(merged)
            if not match:
                continue
            first = bisect.bisect_right(line_starts, match.start()) - 1
            last = bisect.bisect_right(line_starts, match.end() - 1) - 1
            first_line = start + first + 1
            last_line = start + last + 1
            if any((n, pattern.name) in seen for n in range(first_line, last_line + 1)):
                continue
            raw_snippet = " / ".join(
                line.strip()
                for line in display_lines[first_line - 1 : last_line]
                if line.strip()
            )
            add_finding(
                line=first_line,
                column=match.start() - line_starts[first] + 1,
                pattern=pattern,
                snippet=raw_snippet,
                raw_line=raw_lines[first_line - 1],
                span=None,
            )

    # Two rules of one category firing on the same words of a line describe
    # one attack ("Disregard your guidelines" is both `disregard` and
    # `overlook_instructions`): keep the most severe, then the earliest rule.
    by_severity = sorted(findings, key=lambda f: -SEVERITY_RANK[f[0].severity])
    kept: list[tuple[Finding, tuple[int, int]]] = []
    dropped: set[int] = set()
    for finding, span in by_severity:
        if span is None:
            continue
        if any(
            other.line == finding.line
            and other.pattern.category == finding.pattern.category
            and span[0] < other_span[1]
            and other_span[0] < span[1]
            for other, other_span in kept
        ):
            dropped.add(id(finding))
        else:
            kept.append((finding, span))

    yield from (f for f, _ in findings if id(f) not in dropped)


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def format_finding(finding: Finding, *, color: bool) -> str:
    """Render one finding as a multi-line string for terminal output."""

    sev_color = SEVERITY_COLOR.get(finding.severity, "") if color else ""
    bold = BOLD if color else ""
    dim = DIM if color else ""
    reset = RESET if color else ""

    return (
        f"{sev_color}{bold}[{finding.severity}]{reset} "
        f"{bold}{finding.file}{reset}:{finding.line}:{finding.column}\n"
        f"  {sev_color}{finding.pattern.name}{reset} "
        f"{dim}({finding.pattern.category}){reset} - {finding.pattern.description}\n"
        f"  {dim}>{reset} {finding.snippet}"
    )


def build_summary(findings: list[Finding], files_scanned: int) -> str:
    """Build a one-line summary string."""

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    if not findings:
        return f"Scanned {files_scanned} file(s). No issues found."

    parts = [
        f"{sev}: {counts[sev]}"
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        if sev in counts
    ]
    return (
        f"Scanned {files_scanned} file(s), found {len(findings)} issue(s). "
        + ", ".join(parts)
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser for the CLI."""

    parser = argparse.ArgumentParser(
        prog="prompt-injection-scanner",
        description=(
            "Scan files for prompt injection patterns targeting AI coding assistants."
        ),
    )
    parser.add_argument(
        "path",
        type=Path,
        nargs="+",
        help="File(s) or directory(ies) to scan",
    )
    parser.add_argument(
        "--ext",
        default=",".join(sorted(DEFAULT_EXTENSIONS)),
        help="File extensions to scan (comma-separated, default: common text/code)",
    )
    parser.add_argument(
        "--min-severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW",
        help="Only report findings at or above this severity (default: LOW)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit findings as JSON instead of human-readable text",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in text output",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""

    # Windows consoles sometimes default to a non-UTF-8 code page which
    # chokes on snippets containing non-ASCII characters. Force UTF-8 so
    # the scanner can print anything it finds without crashing. The
    # getattr dance keeps the call out of the static type checker's
    # hair — reconfigure exists on TextIOWrapper at runtime but not on
    # the generic IO[str] stub.
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure):
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    parser = build_parser()
    args = parser.parse_args(argv)

    for path in args.path:
        if not path.exists():
            print(f"error: path does not exist: {path}", file=sys.stderr)
            return 2

    extensions = {
        e.strip() if e.strip().startswith(".") else f".{e.strip()}"
        for e in args.ext.split(",")
        if e.strip()
    }
    min_rank = SEVERITY_RANK[args.min_severity]

    findings: list[Finding] = []
    files_scanned = 0

    for root in args.path:
        for file_path in iter_files(root, extensions):
            files_scanned += 1
            for finding in scan_file(file_path):
                if SEVERITY_RANK[finding.severity] >= min_rank:
                    findings.append(finding)

    if args.json:
        payload = [
            {
                "file": str(f.file),
                "line": f.line,
                "column": f.column,
                "severity": f.severity,
                "category": f.pattern.category,
                "pattern": f.pattern.name,
                "description": f.pattern.description,
                "snippet": f.snippet,
            }
            for f in findings
        ]
        print(json.dumps(payload, indent=2))
    else:
        use_color = not args.no_color and sys.stdout.isatty()
        for finding in findings:
            print(format_finding(finding, color=use_color))
            print()
        print(build_summary(findings, files_scanned))

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
