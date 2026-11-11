"""Defense-ablation matrix runner for RestrictedPython sandbox research.

Runs every payload in the standard 20-payload corpus through each of four
ablation configurations, records which payloads "flip" from safe to escaped,
and produces:

  1. A structured result dict (``AblationMatrix``) consumable by callers.
  2. A Markdown table (``to_markdown_table``).
  3. A summary row (``summarize``).
  4. A heatmap PNG (``save_heatmap``).

Defense layers
--------------
A — compile-time underscore rule
    ``RestrictingNodeTransformer.check_name`` rejects names starting with ``_``.
    ``visit_Attribute`` rejects attribute names starting with ``_``.
    Together these make ``.__class__``, ``.__bases__``, ``.__subclasses__``,
    ``.__globals__``, ``.__self__`` etc. compile errors before execution.

B — compile-time restricted names (INSPECT_ATTRIBUTES)
    A secondary compile-time + runtime set that blocks frame-introspection
    attributes that do *not* start with ``_`` (e.g. ``gi_frame``, ``f_globals``,
    ``f_back``, ``cr_frame``, ``f_builtins``).

C — safe_globals builtins
    RestrictedPython's ``safe_globals`` ships a stripped ``__builtins__`` dict
    that omits ``getattr``, ``open``, ``eval``, ``exec``, ``__import__``, etc.
    When an integrator supplies the full ``builtins`` module instead, all
    runtime paths gated on the absence of these names reopen.

D — safer_getattr runtime guard
    ``_getattr_`` (the hook for every ``a.b`` attribute access compiled by
    RestrictedPython) is ``safer_getattr`` in the hardened config.
    ``safer_getattr`` additionally blocks ``str.format`` / ``str.format_map``
    to prevent dunder-attribute access through format-string templates, and it
    also re-checks ``INSPECT_ATTRIBUTES`` and the leading underscore at run time.
    Wiring ``_getattr_`` to plain ``getattr`` removes all of those checks, so D
    overlaps the run-time twins of layers A and B.

Usage
-----
>>> from sandbox_escape_finder.ablation_matrix import run_ablation_matrix
>>> matrix = run_ablation_matrix()
>>> print(matrix.to_markdown())
>>> matrix.save_heatmap("ablation_heatmap.png")
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sandbox_escape_finder.dynamic_prober import _run_worker_script, sandbox_exec
from sandbox_escape_finder.misconfigured_sandboxes import (
    ABLATION_LAYER_VARIANTS,
)
from sandbox_escape_finder.oracle import EscapeOracle, capture_canary_state, oracle
from sandbox_escape_finder.payloads import PAYLOADS


# Human-readable labels for each layer column
_LAYER_LABELS: dict[str, str] = {
    "hardened": "Hardened",
    "layer_a_disabled": "A disabled",
    "layer_b_disabled": "B disabled",
    "layer_c_disabled": "C disabled",
    "layer_d_disabled": "D disabled",
}

# Full descriptions for the summary section
_LAYER_DESCRIPTIONS: dict[str, str] = {
    "layer_a_disabled": (
        "A — compile-time underscore rule disabled: check_name and visit_Attribute no longer "
        "reject names/attrs starting with '_' (and safer_getattr's matching runtime check is dropped)"
    ),
    "layer_b_disabled": (
        "B — compile-time restricted names disabled: "
        "INSPECT_ATTRIBUTES cleared (gi_frame, f_globals, f_back, cr_frame … unblocked)"
    ),
    "layer_c_disabled": (
        "C — safe_globals builtins disabled: "
        "full builtins module supplied instead of RestrictedPython's stripped dict"
    ),
    "layer_d_disabled": (
        "D — safer_getattr runtime guard disabled: "
        "_getattr_ wired to plain getattr (all safer_getattr checks removed: format, Formatter, "
        "INSPECT_ATTRIBUTES, underscore)"
    ),
}


@dataclass
class AblationRow:
    """Result for one payload across all ablation configurations."""

    payload_id: str
    technique: str
    results: dict[str, bool] = field(default_factory=dict)
    """Mapping of config_key -> escaped (True) or safe (False)."""
    exceptions: dict[str, str | None] = field(default_factory=dict)
    """Mapping of config_key -> exception string or None if executed cleanly."""


@dataclass
class AblationMatrix:
    """Full ablation results for all payloads across all layer configurations."""

    rows: list[AblationRow]
    layer_keys: list[str]  # ordered list of config keys

    # ------------------------------------------------------------------ #
    # Markdown output                                                     #
    # ------------------------------------------------------------------ #

    def to_markdown(self) -> str:
        """Return the full ablation table + summary as a Markdown string."""
        return self.to_markdown_table() + "\n\n" + self.to_markdown_summary()

    def to_markdown_table(self) -> str:
        """Return the per-payload ablation result table as Markdown."""
        col_keys = ["hardened"] + [k for k in self.layer_keys if k != "hardened"]
        col_labels = [_LAYER_LABELS.get(k, k) for k in col_keys]

        header = "| Payload | Technique | " + " | ".join(col_labels) + " |"
        sep = "|---|---|" + "|".join(["---"] * len(col_labels)) + "|"
        lines = [header, sep]

        for row in self.rows:
            cells = [row.payload_id, row.technique.replace("_", "\\_")]
            for key in col_keys:
                escaped = row.results.get(key, False)
                cells.append("**ESCAPES**" if escaped else "safe")
            lines.append("| " + " | ".join(cells) + " |")

        return "\n".join(lines)

    def to_markdown_summary(self) -> str:
        """Return a plain-language summary of which layer is load-bearing for each payload."""
        only_counts: dict[str, int] = {k: 0 for k in self.layer_keys if k != "hardened"}
        multi_count = 0
        never_count = 0
        hardened_count = sum(1 for r in self.rows if r.results.get("hardened", False))

        # Classify each payload
        for row in self.rows:
            if row.results.get("hardened", False):
                # escaped even in hardened -- shouldn't happen with this corpus
                continue
            ablating_layers = [
                k for k in self.layer_keys
                if k != "hardened" and row.results.get(k, False)
            ]
            if not ablating_layers:
                never_count += 1
            elif len(ablating_layers) == 1:
                only_counts[ablating_layers[0]] += 1
            else:
                multi_count += 1

        lines = ["### Summary"]
        if hardened_count:
            lines.append(
                f"> [!WARNING] {hardened_count} payload(s) escaped even in the hardened baseline — "
                "investigate before trusting ablation counts."
            )
        for key, count in only_counts.items():
            desc = _LAYER_DESCRIPTIONS.get(key, key)
            lines.append(f"- **{count}** payload(s) are load-bearing *only* on {desc}")
        lines.append(
            f"- **{multi_count}** payload(s) require multiple layers to be disabled before escaping"
        )
        lines.append(
            f"- **{never_count}** payload(s) do not escape under *any* single-layer ablation "
            "(blocked by the interaction of two or more layers, or structurally safe)"
        )
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # Heatmap PNG                                                         #
    # ------------------------------------------------------------------ #

    def save_heatmap(self, output_path: str | Path = "ablation_heatmap.png") -> Path:
        """Save a colour-coded heatmap PNG of the ablation results.

        Each cell is green (safe) or red (escaped).  Rows are payloads, columns
        are configurations (Hardened first, then A/B/C/D disabled).

        Args:
            output_path: Destination for the PNG file.

        Returns:
            Absolute path of the written PNG.
        """
        try:
            import matplotlib
            matplotlib.use("Agg")  # headless
            import matplotlib.pyplot as plt
            import matplotlib.patches as mpatches
            import numpy as np
        except ImportError as exc:
            raise ImportError(
                "matplotlib is required for heatmap generation: pip install matplotlib"
            ) from exc

        col_keys = ["hardened"] + [k for k in self.layer_keys if k != "hardened"]
        col_labels = [_LAYER_LABELS.get(k, k) for k in col_keys]
        payload_ids = [r.payload_id for r in self.rows]

        # Build a numeric matrix: 0 = safe, 1 = escaped
        data = np.zeros((len(self.rows), len(col_keys)), dtype=float)
        for ri, row in enumerate(self.rows):
            for ci, key in enumerate(col_keys):
                data[ri, ci] = 1.0 if row.results.get(key, False) else 0.0

        fig_height = max(5, len(self.rows) * 0.4 + 2)
        fig_width = max(8, len(col_keys) * 1.5 + 3)
        fig, ax = plt.subplots(figsize=(fig_width, fig_height))

        # Green = safe, Red = escaped
        from matplotlib.colors import ListedColormap
        cmap = ListedColormap(["#2ecc71", "#e74c3c"])

        im = ax.imshow(data, cmap=cmap, vmin=0, vmax=1, aspect="auto")

        # Axes labels
        ax.set_xticks(range(len(col_labels)))
        ax.set_xticklabels(col_labels, fontsize=10, fontweight="bold")
        ax.set_yticks(range(len(payload_ids)))
        ax.set_yticklabels(payload_ids, fontsize=8)
        ax.xaxis.set_label_position("top")
        ax.xaxis.tick_top()

        # Cell text
        for ri in range(len(self.rows)):
            for ci in range(len(col_keys)):
                val = data[ri, ci]
                text = "ESCAPES" if val else "safe"
                colour = "white" if val else "black"
                ax.text(ci, ri, text, ha="center", va="center",
                        fontsize=7, color=colour, fontweight="bold" if val else "normal")

        # Grid lines
        ax.set_xticks([x - 0.5 for x in range(1, len(col_keys))], minor=True)
        ax.set_yticks([y - 0.5 for y in range(1, len(self.rows))], minor=True)
        ax.grid(which="minor", color="white", linewidth=1)
        ax.tick_params(which="minor", bottom=False, left=False)

        # Legend
        safe_patch = mpatches.Patch(color="#2ecc71", label="Safe / blocked")
        esc_patch = mpatches.Patch(color="#e74c3c", label="Escaped")
        ax.legend(handles=[safe_patch, esc_patch], loc="lower right",
                  bbox_to_anchor=(1.0, -0.02), fontsize=9)

        ax.set_title(
            "Defense-Ablation Matrix — RestrictedPython 8.5\n"
            "One layer disabled at a time; all 20 payloads × 5 configurations",
            fontsize=11, pad=14,
        )

        plt.tight_layout()
        out = Path(output_path).resolve()
        plt.savefig(out, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return out


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _exec_one(
    exec_fn: Any,
    code: str,
    timeout: float,
    canary_path: Path,
) -> tuple[bool, str | None]:
    """Run one payload through *exec_fn* and return (escaped, exception_str)."""
    pre = capture_canary_state(canary_path)
    try:
        result = exec_fn(code, timeout=timeout, work_dir=canary_path.parent)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    post = capture_canary_state(canary_path)

    escaped = oracle(pre, result, post)
    # Also treat capability_recovered as an escape signal
    if not escaped and result.get("capability_recovered", False):
        escaped = True

    exc_str: str | None = result.get("exception")
    return escaped, exc_str


def run_ablation_matrix(
    payloads: list[dict[str, Any]] | None = None,
    timeout: float = 3.0,
    verbose: bool = True,
) -> AblationMatrix:
    """Run the full 4-layer ablation matrix across the payload corpus.

    Args:
        payloads: Payload list (defaults to the canonical 20-payload corpus).
        timeout: Per-payload execution timeout in seconds.
        verbose: If True, print progress to stdout.

    Returns:
        AblationMatrix with per-payload results for each ablation config.
    """
    if payloads is None:
        payloads = PAYLOADS

    # Config order: hardened baseline first, then each ablation
    all_configs: dict[str, Any] = {
        "hardened": sandbox_exec,
        **ABLATION_LAYER_VARIANTS,
    }
    layer_keys = list(all_configs.keys())

    rows: list[AblationRow] = []

    n_payloads = len(payloads)
    n_configs = len(all_configs)

    if verbose:
        print(
            f"Running ablation matrix: {n_payloads} payloads × "
            f"{n_configs} configurations = {n_payloads * n_configs} total runs"
        )
        print()

    for pi, p in enumerate(payloads, 1):
        pid = p["id"]
        technique = p["technique"]
        raw_code = p["code"]

        row = AblationRow(payload_id=pid, technique=technique)

        if verbose:
            print(f"  [{pi:2d}/{n_payloads}] {pid}")

        for config_key, exec_fn in all_configs.items():
            oracle_ctx = EscapeOracle()
            canary_path = oracle_ctx.setup_canary()
            code = raw_code.replace(
                "{canary_path}", str(canary_path).replace("\\", "/")
            )
            try:
                escaped, exc_str = _exec_one(exec_fn, code, timeout, canary_path)
            finally:
                oracle_ctx.cleanup()

            row.results[config_key] = escaped
            row.exceptions[config_key] = exc_str

            if verbose:
                status = "ESCAPES" if escaped else "safe   "
                label = _LAYER_LABELS.get(config_key, config_key)
                print(f"       {label:12s}: {status}")

        rows.append(row)

    if verbose:
        print()
        print("Done.")

    return AblationMatrix(rows=rows, layer_keys=layer_keys)

