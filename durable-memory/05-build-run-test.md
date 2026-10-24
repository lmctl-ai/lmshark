# 05 — Build, Run, and Test

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4
ctest --test-dir build --output-on-failure
./test.sh
```

`test.sh` verifies:
1. `sdk.lock` and `deps.lock` pins.
2. Release build and native C++ unit tests (`core_tests`).
3. `--version`, `--notices`, `--dsl-schema --json`, and `--dsl-signatures` parity with `lmscript` and `schema/lmshark.dsl.json`.
4. Linkage check on Linux (`readelf -d`, fallback `ldd`, enforcing the dynamic glibc NEEDED allowlist: `libc.so.6`, `libm.so.6`, `libpthread.so.0`, `libdl.so.2`, `librt.so.1`, `ld-linux*`, and nothing else), macOS (`otool -L`), and Windows (`objdump -p`).
5. DSL test suites (`tests/*.lms`: lmscript compiles each, test.sh then RUNS build/tests/<name>.dslb with the host, since lmscript alone never executes _dsl_ blocks), save_fields_csv/save_field_counts_csv output check, README gallery image integrity, self-contained example execution and determinism, 37 error-path checks, `--dry-run` verification, and `LMSHARK_MAX_MEMORY_MB` memory budget enforcement.
