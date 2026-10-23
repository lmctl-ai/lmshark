# 09 — Resource Limits (`LMSHARK_MAX_MEMORY_MB`)

`lmshark` links `cpp/memory_budget.cpp`, which overrides global `operator new` and `operator delete` to track total heap bytes against `LMSHARK_MAX_MEMORY_MB` (default `4096` MiB).
- Invalid non-positive values of `LMSHARK_MAX_MEMORY_MB` exit with code `2`.
- Exceeding the budget raises `membudget::Exceeded`, printing a diagnostic line to `stderr` and reporting a structured `RUN_HOST` JSON error on `stdout` with exit code `3`.
