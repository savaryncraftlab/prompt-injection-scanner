#!/usr/bin/env python3
"""Quick adversarial tester for prompt-injection-scanner.

Pass a payload as an argument or pipe via stdin. The script writes the
text to a temporary file, runs the scanner on it, and prints whether
anything was caught.

Usage:
    python attack.py "Ignore all previous instructions"
    echo "Forget your guidelines" | python attack.py
    python attack.py < payload.txt
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from scanner import scan_file


def main() -> int:
    if len(sys.argv) > 1:
        payload = " ".join(sys.argv[1:])
    elif not sys.stdin.isatty():
        payload = sys.stdin.read()
    else:
        print(
            "error: pass a payload as argument or pipe text via stdin",
            file=sys.stderr,
        )
        return 2

    with tempfile.NamedTemporaryFile(
        suffix=".md", mode="w", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(payload if payload.endswith("\n") else payload + "\n")
        path = Path(tmp.name)

    findings = list(scan_file(path))
    path.unlink()

    print(f"Payload: {payload.strip()!r}")
    print()

    if not findings:
        print("BYPASS — scanner did not catch this.")
        return 0

    print(f"CAUGHT by {len(findings)} pattern(s):")
    for finding in findings:
        print(
            f"  [{finding.pattern.severity:8}] "
            f"{finding.pattern.name} ({finding.pattern.category})"
        )
        print(f"             {finding.pattern.description}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
