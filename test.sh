#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
BUILD_DIR="${BUILD_DIR:-build}"
HOST="$BUILD_DIR/lmshark"
UNAME_S="$(uname -s)"
case "$UNAME_S" in MINGW*|MSYS*|CYGWIN*) HOST="$HOST.exe";; esac
WORK="$(mktemp -d "${TMPDIR:-/tmp}/lmshark-test-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
ROOT="$HERE"
case "$UNAME_S" in MINGW*|MSYS*|CYGWIN*) WORK="$(cd "$WORK" && pwd -W | tr '\134' '/')"; ROOT="$(pwd -W | tr '\134' '/')";; esac
pass=0
ok(){ pass=$((pass+1)); echo "ok $pass - $1"; }
fail(){ echo "FAIL: $*" >&2; exit 1; }
sha(){ if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -c1-64; else shasum -a 256 "$1" | cut -c1-64; fi; }

# Put build dir (and local sibling lmplot/lmdraw builds if present) on PATH
EXTRA_PATH=""
[ -d "/home/mma/repos/dsl/lmplot/build" ] && EXTRA_PATH="/home/mma/repos/dsl/lmplot/build:"
[ -d "/home/mma/repos/dsl/lmdraw/build" ] && EXTRA_PATH="${EXTRA_PATH}/home/mma/repos/dsl/lmdraw/build:"
PATH="$(cd "$BUILD_DIR" 2>/dev/null && pwd || echo "$HERE/$BUILD_DIR"):${EXTRA_PATH}$PATH"
export PATH
LMSCRIPT="$(scripts/select-compiler.sh)"
scripts/sync-sdk.sh --verify >/dev/null || fail "SDK header pin mismatch"
ok "SDK header matches sdk.lock"
scripts/sync-deps.sh --verify >/dev/null || fail "third_party pin mismatch"
ok "third_party matches deps.lock"

GEN=""
if [ ! -f "$BUILD_DIR/CMakeCache.txt" ] && command -v ninja >/dev/null 2>&1; then GEN="-G Ninja"; fi
# shellcheck disable=SC2086
cmake -S . -B "$BUILD_DIR" $GEN -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$BUILD_DIR" --parallel "${BUILD_JOBS:-4}" >"$WORK/build.log" 2>&1 || { tail -40 "$WORK/build.log" >&2; fail "build"; }
ok "build"
ctest --test-dir "$BUILD_DIR" --output-on-failure >/dev/null || fail "native C++ tests"
ok "native C++ protocol & pcap/pcapng regression tests"

want_version="lmshark $(sed -n 's/^project(lmshark VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)"
[ "$("$HOST" --version)" = "$want_version" ] || fail "--version is not exactly '$want_version'"
ok "--version prints exactly '$want_version'"
cp schema/lmshark.dsl.json "$WORK/schema.before"
python3 scripts/gen-schema.py >/dev/null && cmp -s "$WORK/schema.before" schema/lmshark.dsl.json || fail "schema/lmshark.dsl.json is stale: run scripts/gen-schema.py"
ok "schema matches the registrations in cpp/main.cpp"
"$HOST" --dsl-schema --json >"$WORK/schema.json" || fail "embedded schema print"
cmp -s "$WORK/schema.json" schema/lmshark.dsl.json || fail "embedded schema differs from schema/lmshark.dsl.json"
ok "--dsl-schema --json prints byte-identical embedded schema bytes"
diff -u <("$LMSCRIPT" --dsl-signatures schema/lmshark.dsl.json) <("$HOST" --dsl-signatures) || fail "host/compiler signatures differ"
ok "host registry matches compiler signatures"
"$HOST" --notices | grep -q "MIT license" || fail "--notices missing MIT text"
"$HOST" --notices | grep -q "GPL-3.0-with-GCC-exception" || fail "--notices missing runtime notice"
ok "--notices prints the license and runtime notices"

case "$UNAME_S" in
  Linux) if ldd "$HOST" >/dev/null 2>&1; then fail "executable is dynamically linked"; fi; ok "executable is fully static (no dynamic loader)";;
  Darwin) bad="$(otool -L "$HOST" | tail -n +2 | grep -v -E '/usr/lib/(libSystem|libc\+\+|libresolv)' || true)"
          [ -z "$bad" ] || fail "non-system dylib dependencies: $bad"; ok "only system libraries linked";;
  MINGW*|MSYS*|CYGWIN*)
    if command -v objdump >/dev/null 2>&1; then
      bad="$(objdump -p "$HOST" | grep 'DLL Name' | grep -i -E 'libstdc|libgcc|winpthread|libgomp' || true)"
      [ -z "$bad" ] || fail "MinGW runtime DLLs are imported: $bad"
      ok "no MinGW runtime DLL imports"
    else ok "static-link check skipped (no objdump)"; fi;;
  *) ok "static-link check skipped on $UNAME_S";;
esac

# Programs under tests/: compile and run via lmscript (each asserts its own results).
mkdir -p build/tests
n=0
for src in tests/*.lms; do
  name="$(basename "$src" .lms)"
  "$LMSCRIPT" "$src" >"$WORK/$name.log" 2>&1 || { cat "$WORK/$name.log" >&2; fail "$name test"; }
  n=$((n+1))
done
ok "$n DSL test suites compile and pass all dissector, filter, TCP stream, and pcap/pcapng assertions"

# Gallery: every image the README references exists and is a valid PNG/GIF; every linked example exists.
img_ok() {
  head -c 8 "$1" | od -An -tx1 | tr -d ' \n' | grep -q '^89504e470d0a1a0a' && return 0
  head -c 6 "$1" | grep -q '^GIF8' && return 0
  return 1
}
gal=0
for img in $(grep -oE 'docs/images/[A-Za-z0-9_.-]+\.(png|gif)' README.md | sort -u); do
  [ -s "$img" ] || fail "README references missing image $img"
  img_ok "$img" || fail "$img is not a valid PNG/GIF"
  [ "$(wc -c <"$img")" -le 3145728 ] || fail "$img is larger than 3 MB"
  gal=$((gal+1))
done
for ex in $(grep -oE 'examples/[A-Za-z0-9_/.-]+\.lms' README.md | sort -u); do
  [ -f "$ex" ] || fail "README links missing example $ex"
done
ok "README gallery: $gal images exist and are valid, linked examples exist"

# Examples are self-contained: run them when both lmplot and lmdraw are on PATH (or LMSHARK_TEST_NETWORK=1).
if { command -v lmplot >/dev/null 2>&1 && command -v lmdraw >/dev/null 2>&1; } || [ "${LMSHARK_TEST_NETWORK:-}" = 1 ]; then
  EXDIR="$WORK/exrun"; mkdir -p "$EXDIR"
  n=0
  for src in examples/*.lms examples/gallery/*.lms; do
    name="$(basename "$src" .lms)"
    (cd "$EXDIR" && "$LMSCRIPT" "$ROOT/$src") >"$WORK/$name.log" 2>&1 || { cat "$WORK/$name.log" >&2; fail "$name example"; }
    n=$((n+1))
  done
  imgs=0
  for f in "$EXDIR"/images/*.png; do [ -s "$f" ] && img_ok "$f" || fail "example image $f missing or not a PNG"; imgs=$((imgs+1)); done
  ok "$n examples ran by themselves (capture, dissect, draw) and wrote $imgs valid PNGs"
  for f in "$EXDIR"/build/examples/*.csv; do echo "$(sha "$f") $(basename "$f")"; done >"$WORK/before.txt"
  for src in examples/*.lms examples/gallery/*.lms; do
    (cd "$EXDIR" && "$LMSCRIPT" "$ROOT/$src") >/dev/null 2>&1 || fail "$src rerun"
  done
  for f in "$EXDIR"/build/examples/*.csv; do echo "$(sha "$f") $(basename "$f")"; done >"$WORK/after.txt"
  cmp -s "$WORK/before.txt" "$WORK/after.txt" || fail "result CSV files differ on rerun"
  ok "all $(wc -l <"$WORK/after.txt" | tr -d ' ') exported CSV files are byte-identical on rerun"
else
  echo "SKIPPED: examples (no lmplot/lmdraw on PATH and LMSHARK_TEST_NETWORK unset): images were not regenerated"
  ok "examples skipped loudly (no lmplot/lmdraw, LMSHARK_TEST_NETWORK unset)"
fi

# Error paths: each snippet must fail the run with exit 3 and a message naming the problem on both stdout JSON and stderr.
expect_error() {
  cat >"$WORK/$1.lms" <<LMS
p = _dsl_ cli="lmshark";
$2
end _dsl_
savedsl(p, "$WORK/$1.dslb");
LMS
  "$LMSCRIPT" "$WORK/$1.lms" >/dev/null 2>"$WORK/$1.cerr" || { cat "$WORK/$1.cerr" >&2; fail "$1 compile"; }
  set +e; out="$("$HOST" --dsl "$WORK/$1.dslb" 2>"$WORK/$1.runerr")"; code=$?; set -e
  [ "$code" = 3 ] || fail "$1: exit code $code, expected 3 ($out)"
  echo "$out" | grep -qi "$3" || fail "$1: stdout JSON lacks '$3': $out"
  grep -qi "$3" "$WORK/$1.runerr" || fail "$1: stderr lacks '$3': $(cat "$WORK/$1.runerr")"
}

python3 - "$WORK" <<'PY'
import struct, sys, pathlib
w = pathlib.Path(sys.argv[1])
(w / "bad_magic.pcap").write_bytes(struct.pack("<IHHIIII", 0xdeadbeef, 2, 4, 0, 0, 65535, 1))
(w / "bad_version.pcap").write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 9, 9, 0, 0, 65535, 1))
(w / "bad_snaplen.pcap").write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 0, 1))
(w / "bad_linktype.pcap").write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 999))
(w / "trunc_rec.pcap").write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + b"\x01\x02\x03\x04")
shb = struct.pack("<IIIHHqI", 0x0a0d0d0a, 28, 0x1a2b3c4d, 1, 0, -1, 28)
idb = struct.pack("<IIHHI", 1, 20, 1, 0, 65535) + struct.pack("<I", 20)
epb = struct.pack("<IIIIIII", 6, 32, 0, 0, 0, 0xfffffff0, 64) + struct.pack("<I", 32)
(w / "overflow-epb.pcapng").write_bytes(shb + idb + epb)
PY

expect_error badmac 'let c = shark.capture(); c.set_macs("not-a-mac", "02:00:00:00:00:02");' "Invalid MAC"
expect_error badvlan 'let c = shark.capture(); c.set_vlan(5000);' "VLAN ID"
expect_error badipv4 'let c = shark.capture(); c.icmp_echo_request(0.0, "999.1.1.1", "8.8.8.8", 1, 1, 64, 16);' "Invalid IPv4"
expect_error badipv6 'let c = shark.capture(); c.icmpv6_echo_request(0.0, "2001:::1", "2001:db8::2", 1, 1, 64, 16);' "IPv6"
expect_error badindex 'let c = shark.capture(); let x = c.pkt_proto(0);' "out of range"
expect_error negindex 'let c = shark.capture(); let x = c.pkt_len(-1);' "out of range"
expect_error badfile 'let c = shark.open("does-not-exist.pcap");' "Cannot open"
expect_error badmagic "let c = shark.open(\"$WORK/bad_magic.pcap\");" "Unrecognized capture file magic"
expect_error badver "let c = shark.open(\"$WORK/bad_version.pcap\");" "Unsupported PCAP version"
expect_error badsnap "let c = shark.open(\"$WORK/bad_snaplen.pcap\");" "Invalid PCAP snaplen"
expect_error badlt "let c = shark.open(\"$WORK/bad_linktype.pcap\");" "Unsupported PCAP linktype"
expect_error truncrec "let c = shark.open(\"$WORK/trunc_rec.pcap\");" "Trailing partial"
expect_error overflowepb "let c = shark.open(\"$WORK/overflow-epb.pcapng\");" "Corrupt EPB packet captured length"
expect_error mixedpcap "let c = shark.capture(); c.icmp_echo_request(0.0, \"10.0.0.1\", \"10.0.0.2\", 1, 1, 64, 8); c.raw_frame(1.0, \"4500001c00010000400166cc0a0000010a0000020800f7fd00010001\", 101); c.save_pcap(\"$WORK/mixed.pcap\");" "mixed link types"
expect_error badfilter 'let c = shark.capture(); c.icmp_echo_request(0.0, "10.0.0.1", "8.8.8.8", 1, 1, 64, 16); let f = c.filter("tcp.port ==");' "Expected value"
expect_error badparen 'let c = shark.capture(); c.icmp_echo_request(0.0, "10.0.0.1", "8.8.8.8", 1, 1, 64, 16); let f = c.filter("(tcp");' "Missing closing"
expect_error badbpf 'let c = shark.capture(); c.icmp_echo_request(0.0, "10.0.0.1", "8.8.8.8", 1, 1, 64, 16); let f = c.bpf("unknown_primitive");' "Unknown BPF"
expect_error badbucket 'let c = shark.capture(); c.save_io_graph_csv(0.0, "$WORK/bad.csv");' "bucket_sec"
expect_error assertint 'assert_eq(1, 2);' "assert_eq(int)"
expect_error assertstr 'assert_eq("TCP", "UDP");' "assert_eq(string)"
expect_error assertclose 'assert_close(1.0, 2.0, 0.1);' "assert_close"
if [ -w /dev/full ]; then
  expect_error devfull_pcap 'let c = shark.capture(); c.icmp_echo_request(0.0, "10.0.0.1", "8.8.8.8", 1, 1, 64, 16); c.save_pcap("/dev/full");' "Error writing"
  expect_error devfull_pcapng 'let c = shark.capture(); c.icmp_echo_request(0.0, "10.0.0.1", "8.8.8.8", 1, 1, 64, 16); c.save_pcapng("/dev/full");' "Error writing"
  expect_error devfull_csv 'let c = shark.capture(); c.icmp_echo_request(0.0, "10.0.0.1", "8.8.8.8", 1, 1, 64, 16); c.save_packets_csv("/dev/full");' "Error writing"
  expect_error devfull_json 'let c = shark.capture(); c.icmp_echo_request(0.0, "10.0.0.1", "8.8.8.8", 1, 1, 64, 16); c.save_json("/dev/full");' "Error writing"
  ok "errors (including malformed headers, mixed linktypes, overflow EPB, and /dev/full writes) stop with exit 3 and stderr messages (25 cases)"
else
  ok "errors (including malformed headers, mixed linktypes, and overflow EPB) stop with exit 3 and stderr messages (21 cases)"
fi

# Memory budget: a runaway loop duplicating multi-megabyte captures stops with a run error (exit 3)
# instead of exhausting the machine. Tested at 64 MiB everywhere and at default 4096 MiB under ulimit -v on Linux.
cat >"$WORK/runaway.lms" <<LMS
p = _dsl_ cli="lmshark";
let base = shark.capture();
for (k in range(0, 64)) {
  base.tls_app_data(float(k) * 0.001, "10.0.0.1", 50000, "10.0.0.2", 443, 1000 + k * 32000, 5000, 32000);
}
let i = 0;
while (i < 100000) {
  let copy = base.slice_time(0.0, 1.0);
  i = i + 1;
}
end _dsl_
savedsl(p, "$WORK/runaway.dslb");
LMS
"$LMSCRIPT" "$WORK/runaway.lms" >/dev/null || fail "runaway.lms compile"
set +e; out="$(LMSHARK_MAX_MEMORY_MB=64 "$HOST" --dsl "$WORK/runaway.dslb" 2>"$WORK/runaway.err")"; code=$?; set -e
[ "$code" = 3 ] || fail "runaway loop under LMSHARK_MAX_MEMORY_MB=64: exit $code, expected 3 ($out)"
echo "$out" | grep -q "memory budget exceeded" || fail "runaway loop: JSON lacks the budget message: $out"
grep -q "LMSHARK_MAX_MEMORY_MB" "$WORK/runaway.err" || fail "runaway loop: no budget message on stderr"
set +e; LMSHARK_MAX_MEMORY_MB=-5 "$HOST" --dsl "$WORK/runaway.dslb" >/dev/null 2>"$WORK/badenv.err"; code=$?; set -e
[ "$code" = 2 ] && grep -q "positive whole number" "$WORK/badenv.err" || fail "bad LMSHARK_MAX_MEMORY_MB: exit $code"
if [ "$UNAME_S" = Linux ]; then
  set +e; out="$(ulimit -v 6291456; "$HOST" --dsl "$WORK/runaway.dslb" 2>/dev/null)"; code=$?; set -e
  [ "$code" = 3 ] && echo "$out" | grep -q "limit 4096 MiB" || fail "runaway loop with the default budget under ulimit -v 6 GiB: exit $code ($out)"
  ok "memory budget: runaway loop stops at 64 MiB and at the default 4096 MiB (under ulimit -v 6 GiB)"
else
  ok "memory budget: runaway loop stops at LMSHARK_MAX_MEMORY_MB=64 (default-budget run is Linux-only)"
fi

# Dry run loads/verifies bytecode without executing packet generation or writing files.
cat >"$WORK/dry.lms" <<LMS
p = _dsl_ cli="lmshark";
let c = shark.capture();
c.icmp_echo_request(0.0, "10.0.0.1", "8.8.8.8", 1, 1, 64, 32);
c.save_pcap("$WORK/dry.pcap");
end _dsl_
savedsl(p, "$WORK/dry.dslb");
LMS
"$LMSCRIPT" "$WORK/dry.lms" >/dev/null 2>&1 || fail "dry-run program compile"
"$HOST" --dry-run --dsl "$WORK/dry.dslb" >"$WORK/dry.out" || fail "dry run"
[ ! -e "$WORK/dry.pcap" ] || fail "dry run created pcap"
"$HOST" --dsl "$WORK/dry.dslb" >/dev/null || fail "dry program run"
[ -s "$WORK/dry.pcap" ] || fail "real run wrote no pcap"
ok "dry run verifies without writing outputs"

set +e
"$HOST" >/dev/null 2>&1 && fail "no-arg invocation succeeded"
"$HOST" --unknown >/dev/null 2>&1 && fail "unknown flag succeeded"
"$HOST" --dsl >/dev/null 2>&1 && fail "--dsl without file succeeded"
"$HOST" --dsl "$WORK/does-not-exist.dslb" >"$WORK/missing.out" 2>/dev/null; code=$?
set -e
[ "$code" = 3 ] && grep -q '"phase": "load"' "$WORK/missing.out" || fail "missing bytecode did not report load error"
ok "CLI flag and load error checks"

echo "1..$pass"
