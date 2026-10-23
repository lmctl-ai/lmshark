#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PATH="$ROOT/build:/home/mma/repos/dsl/lmplot/build:/home/mma/repos/dsl/lmdraw/build:$PATH"

for f in examples/*.lms examples/gallery/*.lms; do
  echo "Rendering $f ..."
  lmscript "$f"
done

echo "All examples rendered into docs/images/:"
ls -lh docs/images/
