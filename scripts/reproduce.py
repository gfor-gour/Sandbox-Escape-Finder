"""One command: run every experiment and write the pinned artifacts to results/.

    python scripts/reproduce.py      (or: make reproduce)
"""

from __future__ import annotations

import sys
from pathlib import Path

from sandbox_escape_finder.ablation_matrix import run_ablation_matrix
from sandbox_escape_finder.misconfigured_sandboxes import (
    sandbox_exec_exposed_getattr_builtin,
    sandbox_exec_weak_getattr_hook,
)
from sandbox_escape_finder.mutation_fuzzer import run_fuzz
from sandbox_escape_finder.reporting import to_markdown_summary, to_markdown_table
from sandbox_escape_finder.results_report import canary_demo_diff, run_corpus, save_confusion_png

OUT = Path(__file__).resolve().parent.parent / "results"


def section(title: str, table: list) -> str:
    return f"## {title}\n\n{to_markdown_table(table)}\n\n{to_markdown_summary(table)}\n\n"


def write(name: str, text: str) -> None:
    (OUT / name).write_text(text, encoding="utf-8")


def main() -> int:
    OUT.mkdir(exist_ok=True)

    print("[1/5] Experiment 1: hardened configuration")
    hardened = run_corpus(None)
    write("experiment1.md", "# Experiment 1 - hardened RestrictedPython 8.5\n\n" + section("Hardened", hardened))

    print("[2/5] Experiment 2: misconfigured variants")
    v1 = run_corpus(sandbox_exec_weak_getattr_hook)
    v2 = run_corpus(sandbox_exec_exposed_getattr_builtin)
    write(
        "experiment2.md",
        "# Experiment 2 - misconfigured sandboxes\n\n"
        + section("Variant 1: weak _getattr_ hook", v1)
        + section("Variant 2: exposed getattr builtin", v2),
    )
    save_confusion_png({"Hardened": hardened, "Variant 2 (exposed getattr)": v2}, OUT / "CONFUSION_MATRIX.png")

    print("[3/5] Defense-ablation matrix")
    matrix = run_ablation_matrix(timeout=3.0, verbose=False)
    write("ablation.md", "# Defense-ablation matrix\n\n" + matrix.to_markdown_table() + "\n\n" + matrix.to_markdown_summary() + "\n")
    matrix.save_heatmap(OUT / "ablation_heatmap.png")

    print("[4/5] Analyzer robustness (mutation fuzzing)")
    fuzz = run_fuzz()
    write("analyzer_robustness.md", f"# Analyzer robustness\n\n**{fuzz.summary()}**\n")

    print("[5/5] Canary demo diff")
    write("demo_canary_diff.txt", canary_demo_diff())

    escapes = {
        name: sum(r["dynamic_escaped"] or r["capability_recovered"] for r in table)
        for name, table in (("hardened", hardened), ("variant1", v1), ("variant2", v2))
    }
    print(f"\nEscapes: {escapes}; fuzz: {fuzz.summary()}\nArtifacts in {OUT}")
    return 0 if escapes["hardened"] == 0 and fuzz.caught == fuzz.variants else 1


if __name__ == "__main__":
    sys.exit(main())
