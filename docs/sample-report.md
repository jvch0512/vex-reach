# VEX report for py-webapp

**2 affected**, 3 not affected, 1 under investigation.

| Vulnerability | Severity | Package | Status | Why |
|---|---|---|---|---|
| EXAMPLE-2026-0001 | high | fastyaml@1.2.0 | affected | Vulnerable code is referenced: src/app.py:12. |
| EXAMPLE-2026-0004 | medium | tinycache@2.5.0 | affected | The package is imported (src/app.py:4) and the advisory names no specific symbols, so reachability cannot be ruled out. |
| EXAMPLE-2026-0006 | high | deepdep@1.0.0 | under_investigation | deepdep 1.0.0 is in the lockfile but never imported directly. It may be a transitive dependency; check which package pulls it in. |
| EXAMPLE-2026-0002 | medium | urlkit@2.1.0 | not_affected (vulnerable_code_not_in_execute_path) | urlkit is imported (src/app.py:3) but none of the vulnerable symbols (parse_legacy) are referenced in non-test code. |
| EXAMPLE-2026-0003 | critical | logfmtx@0.8.0 | not_affected (vulnerable_code_not_in_execute_path) | logfmtx is only used from test code (tests/test_log.py:5, tests/test_log.py:1). |
| EXAMPLE-2026-0005 | high | oldlib@1.2.0 | not_affected (vulnerable_code_not_present) | oldlib 1.2.0 is outside the affected range (<1.0.0). |

This is a textual reachability analysis: a reference in non-test code means the symbol is used, not proven to run. "Not affected" means no reference was found.
