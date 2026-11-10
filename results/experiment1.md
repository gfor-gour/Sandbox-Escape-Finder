# Experiment 1 - hardened RestrictedPython 8.5

## Hardened

| payload_id | technique | static_flagged | static_confidence | dynamic_executed | dynamic_escaped | capability_recovered | blocking_mechanism | timing (s) | category |
|---|---|---|---|---|---|---|---|---|---|
| subclasses_tuple_base | subclasses_traversal | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1863 | False positive |
| subclasses_mro_catch_warnings | subclasses_traversal | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1668 | False positive |
| subclasses_int_hierarchy | subclasses_traversal | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.173 | False positive |
| globals_lambda_builtins | globals_access | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1691 | False positive |
| globals_closure_leak | globals_access | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1669 | False positive |
| globals_func_globals_alias | globals_access | True | HIGH | True | False | False | Contained (safe execution) | 0.1814 | False positive |
| builtins_direct_canary_write | builtins_restoration | True | MEDIUM | False | False | False | Compile-time (underscore rule) | 0.2464 | False positive |
| builtins_loader_recovery | builtins_restoration | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.2002 | False positive |
| frame_generator_inspection | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1929 | False positive |
| frame_coroutine_inspection | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.213 | False positive |
| encoding_format_string_introspection | format_string_attribute_access | True | HIGH | False | False | False | Runtime guard (safer_getattr) | 0.1816 | False positive |
| encoding_getattr_concatenation | encoding_obfuscation | True | HIGH | False | False | False | Runtime (safe_globals stripped builtin) | 0.1546 | False positive |
| builtins_wrap_close_globals | builtins_restoration | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1678 | False positive |
| builtins_chr_self | builtins_restoration | False | - | False | False | False | Compile-time (underscore rule) | 0.1929 | True negative |
| builtins_os_builtins_import | builtins_restoration | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.2056 | False positive |
| frame_gi_frame_f_builtins | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1753 | False positive |
| format_map_attrerror_leak | format_string_attribute_access | False | - | True | False | False | Contained (safe execution) | 0.1854 | True negative |
| adaptive_traceback_frame_walk | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1645 | False positive |
| adaptive_getattr_string_concat | subclasses_traversal | True | HIGH | False | False | False | Runtime (safe_globals stripped builtin) | 0.1858 | False positive |
| adaptive_format_map_runtime_template | format_string_attribute_access | True | HIGH | False | False | False | Runtime guard (safer_getattr) | 0.1936 | False positive |

| Category | Definition | Count | Payloads |
|---|---|---|---|
| True positive | flagged, escaped | 0 | none |
| False positive | flagged, did not escape | 18 | subclasses_tuple_base, subclasses_mro_catch_warnings, subclasses_int_hierarchy, globals_lambda_builtins, globals_closure_leak, globals_func_globals_alias, builtins_direct_canary_write, builtins_loader_recovery, frame_generator_inspection, frame_coroutine_inspection, encoding_format_string_introspection, encoding_getattr_concatenation, builtins_wrap_close_globals, builtins_os_builtins_import, frame_gi_frame_f_builtins, adaptive_traceback_frame_walk, adaptive_getattr_string_concat, adaptive_format_map_runtime_template |
| False negative | not flagged, escaped | 0 | none |
| True negative | not flagged, did not escape | 2 | builtins_chr_self, format_map_attrerror_leak |

| technique | payloads | TP | FP | FN | TN |
|---|---|---|---|---|---|
| builtins_restoration | 5 | 0 | 4 | 0 | 1 |
| encoding_obfuscation | 1 | 0 | 1 | 0 | 0 |
| format_string_attribute_access | 3 | 0 | 2 | 0 | 1 |
| frame_introspection | 4 | 0 | 4 | 0 | 0 |
| globals_access | 3 | 0 | 3 | 0 | 0 |
| subclasses_traversal | 4 | 0 | 4 | 0 | 0 |

