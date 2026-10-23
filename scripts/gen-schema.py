#!/usr/bin/env python3
"""Regenerate schema/lmshark.dsl.json from the check(...)/checkfn(...) registrations in cpp/main.cpp
so the schema and the host cannot drift. test.sh diffs the registry against the compiler."""
import json, pathlib, re

root = pathlib.Path(__file__).resolve().parent.parent
src = (root / "cpp/main.cpp").read_text()
types = {}
for m in re.finditer(r'(?:check|method)\(\s*r,\s*"(\w+)",\s*"(\w+)",\s*\{([^}]*)\},\s*"(\w+)"', src):
    t, n, ps, rt = m.groups()
    params = [p.strip().strip('"') for p in ps.split(",") if p.strip()]
    types.setdefault(t, {"methods": {}})["methods"].setdefault(n, []).append({"params": params, "returns": rt})
functions = {}
for m in re.finditer(r'(?:checkfn|function)\(\s*r,\s*"(\w+)",\s*\{([^}]*)\},\s*"(\w+)"', src):
    n, ps, rt = m.groups()
    params = [p.strip().strip('"') for p in ps.split(",") if p.strip()]
    functions.setdefault(n, []).append({"params": params, "returns": rt})
schema = {
    "dsl.schema": 2,
    "name": "lmshark",
    "types": types,
    "functions": functions,
    "context": {"shark": "Shark"},
}
with open(root / "schema/lmshark.dsl.json", "w", newline="\n") as f:
    f.write(json.dumps(schema, indent=2) + "\n")
print({t: len(v["methods"]) for t, v in types.items()})
