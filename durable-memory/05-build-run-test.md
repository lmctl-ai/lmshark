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
4. Static linking check on Linux (`ldd`), macOS (`otool -L`), and Windows (`objdump -p`).
5. DSL test suite (`tests/*.lms`), README gallery image integrity, self-contained example execution and determinism, 14 error-path checks, `--dry-run` verification, and `LMSHARK_MAX_MEMORY_MB` memory budget enforcement.
