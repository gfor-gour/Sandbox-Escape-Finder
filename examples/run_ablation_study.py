"""Experiment 3: defense-ablation matrix across all four RestrictedPython layers.

Runs every payload in the standard 20-payload corpus through five sandbox
configurations in sequence:

  - Hardened baseline (documented RestrictedPython setup, zero escapes)
  - Layer A disabled: compile-time underscore rule removed
  - Layer B disabled: compile-time restricted-names (INSPECT_ATTRIBUTES) cleared
  - Layer C disabled: full builtins supplied instead of safe_globals stripped set
  - Layer D disabled: safer_getattr replaced with plain getattr

Each ablation disables exactly one layer and leaves the other three at their
hardened defaults.  The result shows which payloads are "load-bearing" on
which layer, converting the project from "I found one misconfig that escapes"
into "I mapped the load-bearing defense layer for every payload class in the
corpus" -- a systematic empirical result.

Output
------
  - Printed Markdown table with ESCAPES / safe per cell
  - Summary row: "X payloads only on layer A; Y only on B; ..."
  - ablation_heatmap.png saved in the current directory
"""

from __future__ import annotations

import sys
from pathlib import Path

from sandbox_escape_finder.ablation_matrix import run_ablation_matrix


def main() -> None:
    output_dir = Path(__file__).parent
    heatmap_path = output_dir / "ablation_heatmap.png"

    print("=" * 72)
    print("Experiment 3 — Defense-Ablation Matrix")
    print("RestrictedPython 8.5  •  Python", sys.version.split()[0])
    print("=" * 72)
    print()

    matrix = run_ablation_matrix(timeout=3.0, verbose=True)

    print()
    print("=" * 72)
    print("ABLATION MATRIX TABLE")
    print("=" * 72)
    print()
    print(matrix.to_markdown_table())
    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print()
    print(matrix.to_markdown_summary())
    print()

    try:
        saved = matrix.save_heatmap(heatmap_path)
        print(f"Heatmap saved to: {saved}")
    except ImportError as exc:
        print(f"[heatmap skipped] {exc}")


if __name__ == "__main__":
    main()

