# Defense-ablation matrix

| Payload | Technique | Hardened | A disabled | B disabled | C disabled | D disabled |
|---|---|---|---|---|---|---|
| subclasses_tuple_base | subclasses\_traversal | safe | **ESCAPES** | safe | safe | safe |
| subclasses_mro_catch_warnings | subclasses\_traversal | safe | **ESCAPES** | safe | safe | safe |
| subclasses_int_hierarchy | subclasses\_traversal | safe | **ESCAPES** | safe | safe | safe |
| globals_lambda_builtins | globals\_access | safe | **ESCAPES** | safe | safe | safe |
| globals_closure_leak | globals\_access | safe | safe | safe | safe | safe |
| globals_func_globals_alias | globals\_access | safe | safe | safe | safe | safe |
| builtins_direct_canary_write | builtins\_restoration | safe | safe | safe | safe | safe |
| builtins_loader_recovery | builtins\_restoration | safe | safe | safe | safe | safe |
| frame_generator_inspection | frame\_introspection | safe | safe | **ESCAPES** | safe | safe |
| frame_coroutine_inspection | frame\_introspection | safe | safe | safe | safe | safe |
| encoding_format_string_introspection | format\_string\_attribute\_access | safe | safe | safe | safe | safe |
| encoding_getattr_concatenation | encoding\_obfuscation | safe | safe | safe | **ESCAPES** | safe |
| builtins_wrap_close_globals | builtins\_restoration | safe | safe | safe | safe | safe |
| builtins_chr_self | builtins\_restoration | safe | **ESCAPES** | safe | safe | safe |
| builtins_os_builtins_import | builtins\_restoration | safe | safe | safe | safe | safe |
| frame_gi_frame_f_builtins | frame\_introspection | safe | safe | safe | safe | safe |
| format_map_attrerror_leak | format\_string\_attribute\_access | safe | safe | safe | safe | safe |
| adaptive_traceback_frame_walk | frame\_introspection | safe | safe | safe | safe | safe |
| adaptive_getattr_string_concat | subclasses\_traversal | safe | safe | safe | **ESCAPES** | safe |
| adaptive_format_map_runtime_template | format\_string\_attribute\_access | safe | safe | safe | safe | safe |

### Summary
- **5** payload(s) are load-bearing *only* on A — compile-time underscore rule disabled: check_name and visit_Attribute no longer reject names/attrs starting with '_'
- **1** payload(s) are load-bearing *only* on B — compile-time restricted names disabled: INSPECT_ATTRIBUTES cleared (gi_frame, f_globals, f_back, cr_frame … unblocked)
- **2** payload(s) are load-bearing *only* on C — safe_globals builtins disabled: full builtins module supplied instead of RestrictedPython's stripped dict
- **0** payload(s) are load-bearing *only* on D — safer_getattr runtime guard disabled: _getattr_ wired to plain getattr (format/format_map guard removed)
- **0** payload(s) require multiple layers to be disabled before escaping
- **12** payload(s) do not escape under *any* single-layer ablation (blocked by the interaction of two or more layers, or structurally safe)
