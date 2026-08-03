#!/usr/bin/env python3
"""Read `cargo metadata --no-deps` JSON on stdin.
argv[1] = space-separated privileged crate names.
argv[2] = space-separated trust-plane consumers that MAY depend on privileged crates.
Fails (exit 1) if any package declares a privileged crate as an optional dependency, or if any
package that is neither privileged nor a trust-consumer directly depends on a privileged crate.
Normalizes inline and table TOML dependency forms via cargo metadata."""
import json, sys

priv = set(sys.argv[1].split()) if len(sys.argv) > 1 else set()
allowed = priv | (set(sys.argv[2].split()) if len(sys.argv) > 2 else set())
md = json.load(sys.stdin)
bad = 0
for pkg in md["packages"]:
    name = pkg["name"]
    for d in pkg["dependencies"]:
        dn = d["name"]
        opt = d.get("optional", False)
        if dn in priv and opt:
            print("FAIL: " + name + " declares privileged crate " + dn + " as OPTIONAL (defeats absence-based reasoning)")
            bad = 1
        if dn in priv and name not in allowed and not opt:
            print("FAIL: " + name + " (not a trust-plane consumer) directly depends on privileged " + dn)
            bad = 1
sys.exit(bad)
