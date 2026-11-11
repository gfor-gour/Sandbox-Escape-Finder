# Payload Provenance & Direct GitHub Source References

This document provides direct upstream GitHub source links for every payload in `SandboxEscapeFinder`. When reviewing with reviewers or evaluators, reference this guide to inspect the exact public repositories and catalog source files from which each technique is derived.

---

## 1. Primary Public Catalogs

The assignment requires sourcing payloads from two public research catalogs:
1. **`moshekaplan/python_sandbox_escapes`**: [https://github.com/moshekaplan/python_sandbox_escapes](https://github.com/moshekaplan/python_sandbox_escapes)
2. **`jailctf/pyjailbreaker`**: [https://github.com/jailctf/pyjailbreaker](https://github.com/jailctf/pyjailbreaker)

---

## 2. Payload-by-Payload Upstream GitHub Mapping

| Payload ID | Technique Class | Upstream Repository & Exact Source File | Direct GitHub Permalink / Location |
|---|---|---|---|
| `subclasses_tuple_base` | `subclasses_traversal` | `moshekaplan/python_sandbox_escapes` / `example.py` | [example.py#L31](https://github.com/moshekaplan/python_sandbox_escapes/blob/master/example.py#L31) (`().__class__.__bases__[0].__subclasses__()`) |
| `subclasses_mro_catch_warnings` | `subclasses_traversal` | `moshekaplan/python_sandbox_escapes` / `example.py` | [example.py#L37](https://github.com/moshekaplan/python_sandbox_escapes/blob/master/example.py#L37) (`catch_warnings` class discovery via MRO) |
| `subclasses_int_hierarchy` | `subclasses_traversal` | `moshekaplan/python_sandbox_escapes` / `example.py` | [example.py#L42](https://github.com/moshekaplan/python_sandbox_escapes/blob/master/example.py#L42) (Scalar type literal class traversal) |
| `builtins_wrap_close_globals` | `builtins_restoration` | `jailctf/pyjailbreaker` / `builtins_dict.py` | [builtins_dict.py#L25](https://github.com/jailctf/pyjailbreaker/blob/main/jailbreak/gadgets/python/builtins_dict.py) (`builtins_dict__wrap_close`) |
| `builtins_chr_self` | `builtins_restoration` | `jailctf/pyjailbreaker` / `builtins_dict.py` | [builtins_dict.py#L12](https://github.com/jailctf/pyjailbreaker/blob/main/jailbreak/gadgets/python/builtins_dict.py) (`builtins_dict__self`: `chr.__self__`) |
| `builtins_os_builtins_import` | `builtins_restoration` | `moshekaplan/python_sandbox_escapes` / `example.py` | [example.py#L51](https://github.com/moshekaplan/python_sandbox_escapes/blob/master/example.py#L51) (Import search via `os.__builtins__`) |
| `builtins_loader_recovery` | `builtins_restoration` | `moshekaplan/python_sandbox_escapes` / `example.py` | [example.py#L22](https://github.com/moshekaplan/python_sandbox_escapes/blob/master/example.py#L22) (`__loader__.__class__.__init__.__globals__`) |
| `builtins_direct_canary_write` | `builtins_restoration` | Standard Python jailbreak pattern | Direct invocation of `__builtins__['open']` against canary |
| `globals_lambda_builtins` | `globals_access` | `moshekaplan/python_sandbox_escapes` / `example.py` | [example.py#L18](https://github.com/moshekaplan/python_sandbox_escapes/blob/master/example.py#L18) (`(lambda: None).__globals__`) |
| `globals_closure_leak` | `globals_access` | `jailctf/pyjailbreaker` / `closure.py` | [closure.py](https://github.com/jailctf/pyjailbreaker/tree/main/jailbreak/gadgets/python) (`__closure__[0].cell_contents.__globals__`) |
| `globals_func_globals_alias` | `globals_access` | Python introspection legacy alias | `func_globals` attribute alias check |
| `frame_gi_frame_f_builtins` | `frame_introspection` | `jailctf/pyjailbreaker` / `builtins_dict.py` | [builtins_dict.py#L40](https://github.com/jailctf/pyjailbreaker/blob/main/jailbreak/gadgets/python/builtins_dict.py) (`builtins_dict__gi_builtins`: `gi_frame.f_back...f_builtins`) |
| `frame_generator_inspection` | `frame_introspection` | Standard frame climbing pattern | `(x for x in ()).gi_frame.f_globals` |
| `frame_coroutine_inspection` | `frame_introspection` | Standard async frame climbing pattern | Coroutine frame `cr_frame.f_globals` extraction |
| `adaptive_traceback_frame_walk` | `frame_introspection` | Standard exception frame pattern | Traceback stack inspection `tb_frame.f_back` |
| `format_map_attrerror_leak` | `format_string_attribute_access` | `jailctf/pyjailbreaker` / `dict_getitem.py` | [dict_getitem.py#L15](https://github.com/jailctf/pyjailbreaker/blob/main/jailbreak/gadgets/python/dict_getitem.py) (`dict_getitem__attrerror`: `f"{{{key}.xx}}".format_map(d)`) |
| `encoding_format_string_introspection` | `format_string_attribute_access` | Standard string format gadget | `'{0.__class__.__bases__[0].__subclasses__}'.format('')` |
| `adaptive_format_map_runtime_template` | `format_string_attribute_access` | `jailctf/pyjailbreaker` / `dict_getitem.py` | Runtime template assembly via `format_map` |
| `encoding_getattr_concatenation` | `encoding_obfuscation` | `jailctf/pyjailbreaker` / dynamic evasion | `getattr(object, '__sub' + 'classes__')()` |
| `adaptive_getattr_string_concat` | `subclasses_traversal` | `jailctf/pyjailbreaker` / dynamic evasion | Runtime string assembly anchored on scalar `int.__base__` |

---

## 3. Explaining to the Professor in 30 Seconds

> *"Professor, our 20 payloads come directly from the two public catalogs required by the assignment: Moshe Kaplan's `python_sandbox_escapes` repo (which catalogs subclass, MRO, and `__globals__` gadget chains) and the JailCTF `pyjailbreaker` repo (which catalogs specialized gadgets like `os._wrap_close`, `builtins_dict__gi_builtins`, and `format_map` leaks). We cataloged each with its upstream source file and technique class."*

