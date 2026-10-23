# lmshark Durable Memory Index

- [01-purpose-and-place.md](01-purpose-and-place.md) — Scope, design philosophy, and relationship to Wireshark/tshark.
- [02-libraries-and-licenses.md](02-libraries-and-licenses.md) — Clean-room MIT C++17 implementation and zero-GPL guarantee.
- [03-schema-v0.md](03-schema-v0.md) — `Shark` and `Capture` DSL types, methods, and global functions.
- [04-dissection-and-tcp.md](04-dissection-and-tcp.md) — Wire format parsers (`pcap`/`pcapng`), RFC checksums, L2–L7 dissectors, and TCP stream reassembly/RTT engine.
- [05-build-run-test.md](05-build-run-test.md) — CMake static build, `test.sh`, and verification workflow.
- [06-ci.md](06-ci.md) — 5-platform GitHub Actions matrix and tagged release automation.
- [07-examples.md](07-examples.md) — Visual gallery scripts (`lmplot` + `lmdraw` + `ffmpeg`).
- [08-open-items.md](08-open-items.md) — Future protocol extensions.
- [09-resource-limits.md](09-resource-limits.md) — `LMSHARK_MAX_MEMORY_MB` memory budget enforcement.
