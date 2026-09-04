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
# FLOOR (#219). This gate DISCOVERS its input -- the package set comes from
# `cargo metadata`, not from a code constant -- so it has a zero-input case, and
# it reported `ok` at rc 0 for one: a workspace whose `members = []` yields zero
# packages, no iterations, and a clean bill of health for a dependency graph
# nobody looked at. Demonstrated before this change. A manifest that resolves to
# no packages is a broken invocation, never a clean workspace.
if not md["packages"]:
    print("FAIL: cargo metadata resolved ZERO packages — nothing was examined, so")
    print("  'no optional privileged dependency' is not a finding. Wrong manifest,")
    print("  an empty `members`, or a metadata invocation that silently degraded.")
    sys.exit(1)
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
