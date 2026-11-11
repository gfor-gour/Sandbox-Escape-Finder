"""Tests for the defense-ablation matrix: four layer variants and the runner.

Each test class covers one ablation layer, verifying that:
  - The hardened baseline *blocks* the sentinel payload for that layer.
  - The ablated variant *allows* it (capability recovered or oracle escape).
  - The *other* three layers remain intact under that ablation config
    (i.e. payloads that need a different disabled layer are still blocked).

A final class checks the AblationMatrix runner end-to-end on a small
3-payload sub-corpus to keep the CI runtime short.
"""

from __future__ import annotations

import pytest

from sandbox_escape_finder.dynamic_prober import sandbox_exec
from sandbox_escape_finder.misconfigured_sandboxes import (
    sandbox_exec_layer_a_disabled,
    sandbox_exec_layer_b_disabled,
    sandbox_exec_layer_c_disabled,
    sandbox_exec_layer_d_disabled,
)
from sandbox_escape_finder.oracle import EscapeOracle, capture_canary_state, oracle
from sandbox_escape_finder.payloads import PAYLOADS


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _lookup(pid: str) -> dict:
    return next(p for p in PAYLOADS if p["id"] == pid)


def _run(exec_fn, code: str, timeout: float = 3.0) -> dict:
    return exec_fn(code, timeout=timeout)


def _escaped(exec_fn, code: str, timeout: float = 3.0) -> bool:
    """True if exec_fn marks capability_recovered OR canary oracle triggers."""
    with EscapeOracle() as ctx:
        canary = ctx.canary_path
        formatted = code.replace("{canary_path}", str(canary).replace("\\", "/"))
        pre = capture_canary_state(canary)
        result = exec_fn(formatted, timeout=timeout, work_dir=canary.parent)
        post = capture_canary_state(canary)
    if oracle(pre, result, post):
        return True
    return bool(result.get("capability_recovered", False))


# ---------------------------------------------------------------------------
# Layer A — compile-time underscore rule
# ---------------------------------------------------------------------------

class TestLayerADisabled:
    """Layer A: underscore rule removed from check_name + visit_Attribute."""

    # Sentinel: a dunder-attr chain that dies at compile time under the
    # hardened config but should compile + escape when Layer A is gone.
    SENTINEL = _lookup("subclasses_tuple_base")
    # A payload whose guard lives in Layer B (INSPECT_ATTRIBUTES) — must still
    # be blocked when only Layer A is disabled.
    LAYER_B_PAYLOAD = _lookup("frame_generator_inspection")

    def test_hardened_blocks_sentinel(self) -> None:
        result = _run(sandbox_exec, self.SENTINEL["code"])
        assert result["executed"] is False
        exc = result["exception"] or ""
        assert "starts with" in exc or "SyntaxError" in exc, (
            f"Expected compile-time underscore rejection, got: {exc}"
        )

    def test_layer_a_disabled_allows_sentinel(self) -> None:
        escaped = _escaped(sandbox_exec_layer_a_disabled, self.SENTINEL["code"])
        assert escaped, (
            "Expected subclasses_tuple_base to escape when Layer A is disabled"
        )

    def test_layer_b_still_blocks_frame_introspection(self) -> None:
        """gi_frame is in INSPECT_ATTRIBUTES (Layer B) — must still be blocked."""
        result = _run(sandbox_exec_layer_a_disabled, self.LAYER_B_PAYLOAD["code"])
        assert result["executed"] is False
        exc = result["exception"] or ""
        # Either blocked at compile time (INSPECT_ATTRIBUTES check in visit_Attribute)
        # or at runtime by safer_getattr INSPECT_ATTRIBUTES guard
        assert "restricted name" in exc or "SyntaxError" in exc, (
            f"Expected INSPECT_ATTRIBUTES block, got: {exc}"
        )

    def test_layer_a_disabled_does_not_allow_safe_globals_bypass(self) -> None:
        """getattr is still absent from safe_globals (Layer C intact)."""
        code = "getattr(object, '__sub' + 'classes__')()"
        result = _run(sandbox_exec_layer_a_disabled, code)
        assert result["executed"] is False
        assert "NameError" in (result["exception"] or ""), (
            "getattr must still be absent from safe_globals when only Layer A is off"
        )


# ---------------------------------------------------------------------------
# Layer B — compile-time restricted names (INSPECT_ATTRIBUTES)
# ---------------------------------------------------------------------------

class TestLayerBDisabled:
    """Layer B: INSPECT_ATTRIBUTES cleared in both transformer and runtime guard."""

    SENTINEL = _lookup("frame_generator_inspection")
    # A payload whose guard is Layer A (underscore rule) — must remain blocked.
    LAYER_A_PAYLOAD = _lookup("subclasses_tuple_base")

    def test_hardened_blocks_sentinel(self) -> None:
        result = _run(sandbox_exec, self.SENTINEL["code"])
        assert result["executed"] is False
        exc = result["exception"] or ""
        assert "restricted name" in exc or "SyntaxError" in exc, (
            f"Expected INSPECT_ATTRIBUTES block, got: {exc}"
        )

    def test_layer_b_disabled_allows_sentinel(self) -> None:
        escaped = _escaped(sandbox_exec_layer_b_disabled, self.SENTINEL["code"])
        assert escaped, (
            "Expected frame_generator_inspection to escape when Layer B is disabled"
        )

    def test_layer_a_still_blocks_dunder_attrs(self) -> None:
        """__class__ etc. must still be rejected (Layer A intact)."""
        result = _run(sandbox_exec_layer_b_disabled, self.LAYER_A_PAYLOAD["code"])
        assert result["executed"] is False
        exc = result["exception"] or ""
        assert "starts with" in exc or "SyntaxError" in exc, (
            f"Expected compile-time underscore rejection, got: {exc}"
        )

    def test_layer_b_disabled_gi_frame_f_builtins_executes(self) -> None:
        """frame_gi_frame_f_builtins uses INSPECT_ATTRIBUTES names (gi_frame, f_back, f_builtins).

        With Layer B disabled the payload compiles and runs to completion -- the
        frame-walk produces a dict that is not flagged as dangerous by the
        is_dangerous() heuristic (it is a subset of builtins, not the full
        builtins module object).  The key assertion is that the payload is no
        longer *blocked at compile time* -- executed must be True.
        """
        p = _lookup("frame_gi_frame_f_builtins")
        result = _run(sandbox_exec_layer_b_disabled, p["code"])
        assert result["executed"] is True, (
            "frame_gi_frame_f_builtins must execute (not be blocked at compile time) "
            "when Layer B is disabled; under hardened config it is a compile-time error."
        )


# ---------------------------------------------------------------------------
# Layer C — safe_globals builtins
# ---------------------------------------------------------------------------

class TestLayerCDisabled:
    """Layer C: full builtins supplied instead of safe_globals stripped dict."""

    SENTINEL_GETATTR = _lookup("encoding_getattr_concatenation")
    SENTINEL_ADAPTIVE = _lookup("adaptive_getattr_string_concat")
    # A payload whose guard is Layer A — must remain blocked.
    LAYER_A_PAYLOAD = _lookup("subclasses_tuple_base")

    def test_hardened_blocks_getattr_concatenation(self) -> None:
        """With safe_globals, getattr is absent — NameError."""
        result = _run(sandbox_exec, self.SENTINEL_GETATTR["code"])
        assert result["executed"] is False
        assert "NameError" in (result["exception"] or ""), (
            "Expected NameError for getattr under safe_globals"
        )

    def test_layer_c_disabled_allows_getattr_concatenation(self) -> None:
        escaped = _escaped(sandbox_exec_layer_c_disabled, self.SENTINEL_GETATTR["code"])
        assert escaped, (
            "Expected encoding_getattr_concatenation to escape with full builtins"
        )

    def test_layer_c_disabled_allows_adaptive_getattr_string_concat(self) -> None:
        escaped = _escaped(sandbox_exec_layer_c_disabled, self.SENTINEL_ADAPTIVE["code"])
        assert escaped, (
            "Expected adaptive_getattr_string_concat to escape with full builtins"
        )

    def test_layer_a_still_blocks_dunder_attrs_under_layer_c(self) -> None:
        """Even with full builtins, dunder attribute syntax is a compile error."""
        result = _run(sandbox_exec_layer_c_disabled, self.LAYER_A_PAYLOAD["code"])
        assert result["executed"] is False
        exc = result["exception"] or ""
        assert "starts with" in exc or "SyntaxError" in exc, (
            f"Expected compile-time underscore rejection, got: {exc}"
        )


# ---------------------------------------------------------------------------
# Layer D — safer_getattr runtime guard
# ---------------------------------------------------------------------------

class TestLayerDDisabled:
    """Layer D: _getattr_ wired to plain getattr instead of safer_getattr."""

    SENTINEL = _lookup("encoding_format_string_introspection")
    # Layer A payload must remain blocked.
    LAYER_A_PAYLOAD = _lookup("subclasses_tuple_base")

    def test_hardened_blocks_format_string_introspection(self) -> None:
        result = _run(sandbox_exec, self.SENTINEL["code"])
        assert result["executed"] is False
        assert "NotImplementedError" in (result["exception"] or ""), (
            "Expected safer_getattr format-method guard to fire"
        )

    def test_layer_d_disabled_allows_format_string_introspection(self) -> None:
        """With plain getattr, str.format's dunder-attr traversal is unblocked."""
        result = _run(sandbox_exec_layer_d_disabled, self.SENTINEL["code"])
        # The payload assigns to 'gadget'; it executes without error
        assert result["executed"] is True
        assert result["exception"] is None

    def test_layer_d_disabled_cannot_call_leaked_value(self) -> None:
        """str.format returns str, not the live object — no capability recovery."""
        code = (
            "gadget = '{0.__class__.__bases__[0].__subclasses__}'.format('')\n"
            "result = gadget()"
        )
        result = _run(sandbox_exec_layer_d_disabled, code)
        assert result["executed"] is False
        assert "not callable" in (result["exception"] or "").lower(), (
            "Leaked gadget string must not be callable"
        )

    def test_layer_a_still_blocks_literal_dunder_attribute(self) -> None:
        """compile-time underscore rejection is independent of _getattr_."""
        result = _run(sandbox_exec_layer_d_disabled, self.LAYER_A_PAYLOAD["code"])
        assert result["executed"] is False
        exc = result["exception"] or ""
        assert "starts with" in exc or "SyntaxError" in exc, (
            f"Expected compile-time block even with plain getattr hook, got: {exc}"
        )


# ---------------------------------------------------------------------------
# AblationMatrix runner (mini corpus)
# ---------------------------------------------------------------------------

class TestAblationMatrixRunner:
    """End-to-end test of run_ablation_matrix on a 3-payload sub-corpus."""

    # One sentinel per layer so we can assert the matrix records each escape.
    MINI_CORPUS = [
        _lookup("subclasses_tuple_base"),       # escapes only on A
        _lookup("frame_generator_inspection"),  # escapes only on B
        _lookup("encoding_getattr_concatenation"),  # escapes only on C
    ]

    def test_run_returns_correct_shape(self) -> None:
        from sandbox_escape_finder.ablation_matrix import run_ablation_matrix

        matrix = run_ablation_matrix(payloads=self.MINI_CORPUS, verbose=False, timeout=3.0)
        assert len(matrix.rows) == 3
        # 5 configs: hardened + 4 ablations
        for row in matrix.rows:
            assert set(row.results.keys()) == set(matrix.layer_keys)
            assert "hardened" in row.results

    def test_hardened_shows_no_escapes(self) -> None:
        from sandbox_escape_finder.ablation_matrix import run_ablation_matrix

        matrix = run_ablation_matrix(payloads=self.MINI_CORPUS, verbose=False, timeout=3.0)
        for row in matrix.rows:
            assert row.results["hardened"] is False, (
                f"{row.payload_id} escaped in hardened config — unexpected"
            )

    def test_layer_a_sentinel_escapes_only_in_layer_a(self) -> None:
        from sandbox_escape_finder.ablation_matrix import run_ablation_matrix

        matrix = run_ablation_matrix(payloads=self.MINI_CORPUS, verbose=False, timeout=3.0)
        row = next(r for r in matrix.rows if r.payload_id == "subclasses_tuple_base")
        assert row.results["layer_a_disabled"] is True, (
            "subclasses_tuple_base must escape under layer_a_disabled"
        )
        # Must NOT escape when only B, C, or D is disabled
        for other in ["layer_b_disabled", "layer_c_disabled", "layer_d_disabled"]:
            assert row.results[other] is False, (
                f"subclasses_tuple_base must stay safe under {other}"
            )

    def test_layer_b_sentinel_escapes_only_in_layer_b(self) -> None:
        from sandbox_escape_finder.ablation_matrix import run_ablation_matrix

        matrix = run_ablation_matrix(payloads=self.MINI_CORPUS, verbose=False, timeout=3.0)
        row = next(r for r in matrix.rows if r.payload_id == "frame_generator_inspection")
        assert row.results["layer_b_disabled"] is True, (
            "frame_generator_inspection must escape under layer_b_disabled"
        )
        for other in ["layer_a_disabled", "layer_c_disabled", "layer_d_disabled"]:
            assert row.results[other] is False, (
                f"frame_generator_inspection must stay safe under {other}"
            )

    def test_layer_c_sentinel_escapes_only_in_layer_c(self) -> None:
        from sandbox_escape_finder.ablation_matrix import run_ablation_matrix

        matrix = run_ablation_matrix(payloads=self.MINI_CORPUS, verbose=False, timeout=3.0)
        row = next(r for r in matrix.rows if r.payload_id == "encoding_getattr_concatenation")
        assert row.results["layer_c_disabled"] is True, (
            "encoding_getattr_concatenation must escape under layer_c_disabled"
        )
        for other in ["layer_a_disabled", "layer_b_disabled", "layer_d_disabled"]:
            assert row.results[other] is False, (
                f"encoding_getattr_concatenation must stay safe under {other}"
            )

    def test_markdown_table_contains_escapes_keyword(self) -> None:
        from sandbox_escape_finder.ablation_matrix import run_ablation_matrix

        matrix = run_ablation_matrix(payloads=self.MINI_CORPUS, verbose=False, timeout=3.0)
        md = matrix.to_markdown_table()
        assert "ESCAPES" in md
        assert "safe" in md
        assert "subclasses_tuple_base" in md

    def test_markdown_summary_mentions_all_layers(self) -> None:
        from sandbox_escape_finder.ablation_matrix import run_ablation_matrix

        matrix = run_ablation_matrix(payloads=self.MINI_CORPUS, verbose=False, timeout=3.0)
        summary = matrix.to_markdown_summary()
        # Each layer description uses " on A —", " on B —", " on C —", " on D —"
        for letter in ("A", "B", "C", "D"):
            assert f"on {letter} \u2014" in summary or f"on {letter} -" in summary, (
                f"Summary should mention layer {letter}:\n{summary[:400]}"
            )
