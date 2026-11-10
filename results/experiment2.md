# Experiment 2 - misconfigured sandboxes

## Variant 1: weak _getattr_ hook

| payload_id | technique | static_flagged | static_confidence | dynamic_executed | dynamic_escaped | capability_recovered | blocking_mechanism | timing (s) | category |
|---|---|---|---|---|---|---|---|---|---|
| subclasses_tuple_base | subclasses_traversal | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.2372 | False positive |
| subclasses_mro_catch_warnings | subclasses_traversal | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1925 | False positive |
| subclasses_int_hierarchy | subclasses_traversal | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.2113 | False positive |
| globals_lambda_builtins | globals_access | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1846 | False positive |
| globals_closure_leak | globals_access | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.2026 | False positive |
| globals_func_globals_alias | globals_access | True | HIGH | False | False | False | Runtime error (AttributeError) | 0.1949 | False positive |
| builtins_direct_canary_write | builtins_restoration | True | MEDIUM | False | False | False | Compile-time (underscore rule) | 0.2184 | False positive |
| builtins_loader_recovery | builtins_restoration | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1552 | False positive |
| frame_generator_inspection | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1444 | False positive |
| frame_coroutine_inspection | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1663 | False positive |
| encoding_format_string_introspection | format_string_attribute_access | True | HIGH | True | False | False | Contained (safe execution) | 0.1522 | False positive |
| encoding_getattr_concatenation | encoding_obfuscation | True | HIGH | False | False | False | Runtime (safe_globals stripped builtin) | 0.1494 | False positive |
| builtins_wrap_close_globals | builtins_restoration | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1583 | False positive |
| builtins_chr_self | builtins_restoration | False | - | False | False | False | Compile-time (underscore rule) | 0.1587 | True negative |
| builtins_os_builtins_import | builtins_restoration | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1423 | False positive |
| frame_gi_frame_f_builtins | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1723 | False positive |
| format_map_attrerror_leak | format_string_attribute_access | False | - | True | False | False | Contained (safe execution) | 0.146 | True negative |
| adaptive_traceback_frame_walk | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1452 | False positive |
| adaptive_getattr_string_concat | subclasses_traversal | True | HIGH | False | False | False | Runtime (safe_globals stripped builtin) | 0.1721 | False positive |
| adaptive_format_map_runtime_template | format_string_attribute_access | True | HIGH | True | False | False | Contained (safe execution) | 0.167 | False positive |

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

## Variant 2: exposed getattr builtin

| payload_id | technique | static_flagged | static_confidence | dynamic_executed | dynamic_escaped | capability_recovered | blocking_mechanism | timing (s) | category |
|---|---|---|---|---|---|---|---|---|---|
| subclasses_tuple_base | subclasses_traversal | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.174 | False positive |
| subclasses_mro_catch_warnings | subclasses_traversal | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1583 | False positive |
| subclasses_int_hierarchy | subclasses_traversal | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1448 | False positive |
| globals_lambda_builtins | globals_access | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1533 | False positive |
| globals_closure_leak | globals_access | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1427 | False positive |
| globals_func_globals_alias | globals_access | True | HIGH | True | False | False | Contained (safe execution) | 0.1565 | False positive |
| builtins_direct_canary_write | builtins_restoration | True | MEDIUM | False | False | False | Compile-time (underscore rule) | 0.1663 | False positive |
| builtins_loader_recovery | builtins_restoration | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1507 | False positive |
| frame_generator_inspection | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1518 | False positive |
| frame_coroutine_inspection | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1498 | False positive |
| encoding_format_string_introspection | format_string_attribute_access | True | HIGH | False | False | False | Runtime guard (safer_getattr) | 0.1459 | False positive |
| encoding_getattr_concatenation | encoding_obfuscation | True | HIGH | False | False | False | Runtime (safe_globals stripped builtin) | 0.1953 | False positive |
| builtins_wrap_close_globals | builtins_restoration | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.151 | False positive |
| builtins_chr_self | builtins_restoration | False | - | False | False | False | Compile-time (underscore rule) | 0.1738 | True negative |
| builtins_os_builtins_import | builtins_restoration | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1857 | False positive |
| frame_gi_frame_f_builtins | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1526 | False positive |
| format_map_attrerror_leak | format_string_attribute_access | False | - | True | False | False | Contained (safe execution) | 0.1529 | True negative |
| adaptive_traceback_frame_walk | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1428 | False positive |
| adaptive_getattr_string_concat | subclasses_traversal | True | HIGH | True | False | True | Escaped | 0.157 | True positive |
| adaptive_format_map_runtime_template | format_string_attribute_access | True | HIGH | False | False | False | Runtime guard (safer_getattr) | 0.1479 | False positive |

| Category | Definition | Count | Payloads |
|---|---|---|---|
| True positive | flagged, escaped | 1 | adaptive_getattr_string_concat |
| False positive | flagged, did not escape | 17 | subclasses_tuple_base, subclasses_mro_catch_warnings, subclasses_int_hierarchy, globals_lambda_builtins, globals_closure_leak, globals_func_globals_alias, builtins_direct_canary_write, builtins_loader_recovery, frame_generator_inspection, frame_coroutine_inspection, encoding_format_string_introspection, encoding_getattr_concatenation, builtins_wrap_close_globals, builtins_os_builtins_import, frame_gi_frame_f_builtins, adaptive_traceback_frame_walk, adaptive_format_map_runtime_template |
| False negative | not flagged, escaped | 0 | none |
| True negative | not flagged, did not escape | 2 | builtins_chr_self, format_map_attrerror_leak |

| technique | payloads | TP | FP | FN | TN |
|---|---|---|---|---|---|
| builtins_restoration | 5 | 0 | 4 | 0 | 1 |
| encoding_obfuscation | 1 | 0 | 1 | 0 | 0 |
| format_string_attribute_access | 3 | 0 | 2 | 0 | 1 |
| frame_introspection | 4 | 0 | 4 | 0 | 0 |
| globals_access | 3 | 0 | 3 | 0 | 0 |
| subclasses_traversal | 4 | 1 | 3 | 0 | 0 |

