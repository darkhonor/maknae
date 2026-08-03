#!/usr/bin/env python3
"""Read `cargo metadata --no-deps` JSON on stdin.
argv[1] = space-separated privileged crate names.
argv[2] = space-separated per-consumer allow entries "binary=crate[,crate...]" — which privileged
          crate(s) each trust-plane binary may DIRECTLY depend on.
Fails (exit 1) if any package declares a privileged crate as optional, or if any package directly
depends on a privileged crate it is not permitted to (privileged crates may depend on each other;
each trust consumer may depend only on its allowlisted privileged crate; nothing else may).
Normalizes inline and table TOML dependency forms via cargo metadata."""
import json, sys

priv = set(sys.argv[1].split()) if len(sys.argv) > 1 else set()
allow = {}
for entry in (sys.argv[2].split() if len(sys.argv) > 2 else []):
    k, _, v = entry.partition("=")
    allow[k] = set(v.split(",")) if v else set()

md = json.load(sys.stdin)
bad = 0
for pkg in md["packages"]:
    name = pkg["name"]
    for d in pkg["dependencies"]:
        dn = d["name"]
        if dn not in priv:
            continue
        opt = d.get("optional", False)
        if opt:
            print("FAIL: " + name + " declares privileged crate " + dn + " as OPTIONAL (defeats absence-based reasoning)")
            bad = 1
            continue
        if name in priv:
            continue                      # privileged→privileged is allowed (e.g. kernel→mint)
        if dn in allow.get(name, set()):
            continue                      # this consumer is permitted this exact privileged crate
        print("FAIL: " + name + " directly depends on privileged " + dn + " but is not permitted it (per-consumer allowlist)")
        bad = 1
sys.exit(bad)
