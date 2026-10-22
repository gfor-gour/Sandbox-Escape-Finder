"""Static sanity pass: run StaticAnalyzer over the payload corpus.

Static analysis only; no payload is executed. For each payload this prints its
attributed technique, whether that technique's own detector fires, every
detector that fired, and whether the code parses. Exits non-zero if any
payload fails to parse, since an unparseable payload can never be flagged.

Usage:  python examples/corpus_sanity.py
"""

from __future__ import annotations

import ast
import sys
from collections import Counter

from sandbox_escape_finder.payloads import PAYLOADS
from sandbox_escape_finder.static_analyzer import DETECTOR_REGISTRY, StaticAnalyzer


def main() -> int:
    analyzer = StaticAnalyzer()
    print(f"{'id':40} {'technique':32} {'own':5} fired")
    misses: list[str] = []
    syntax_errors: list[str] = []

    for payload in PAYLOADS:
        try:
            ast.parse(payload["code"])
            parse = "ok"
        except SyntaxError:
            parse = "SYNTAXERR"
            syntax_errors.append(payload["id"])

        technique = payload["technique"]
        fired = sorted({f["technique"] for f in analyzer.scan(payload["code"])})
        if technique in DETECTOR_REGISTRY:
            own = "YES" if technique in fired else "NO"
            if own == "NO":
                misses.append(payload["id"])
        else:
            own = "n/a"
        print(f"{payload['id']:40} {technique:32} {own:5} {fired} parse={parse}")

    print(Counter(p["technique"] for p in PAYLOADS), len(PAYLOADS))
    print("Own-detector misses:", misses)
    print("Syntax errors:", syntax_errors)
    return 1 if syntax_errors else 0


if __name__ == "__main__":
    sys.exit(main())
