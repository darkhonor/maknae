#!/usr/bin/env python3
"""Exact field/type/variant inventory for the per-request mutation grant.

The grant is not configuration output or pre-redacted bytes. Its complete
reachable schema has a separate disclosure decision for every field/variant.
Unsupported Rust shapes fail closed rather than silently becoming opaque leaves.
"""
import re
import sys
from pathlib import Path


def inventory(source):
    source = re.sub(r"//[^\n]*", "", source)
    declarations = {}
    for match in re.finditer(r"pub\s+(struct|enum)\s+(\w+)\s*\{", source):
        depth, end = 1, match.end()
        while depth and end < len(source):
            depth += (source[end] == "{") - (source[end] == "}")
            end += 1
        if depth or match[2] in declarations:
            raise ValueError("unbalanced or duplicate declaration")
        declarations[match[2]] = (match[1], source[match.end():end - 1])
    pending, seen, rows = ["MutationGrant"], set(), []
    primitives = {"u16", "u32", "u64", "String", "Vec<String>"}

    def field_list(body, prefix):
        for field in body.split(","):
            if not field.strip():
                continue
            field = re.sub(r"^\s*pub\s+", "", field)
            field = re.sub(r"\s+", "", field)
            match = re.fullmatch(r"([A-Za-z_]\w*):([A-Za-z_]\w*(?:<String>)?)", field)
            if not match:
                raise ValueError(f"unsupported grant field in {prefix}: {field}")
            name, kind = match.groups()
            rows.append(f"{prefix}.{name}:{kind}")
            if kind not in primitives:
                pending.append(kind)

    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        if name not in declarations:
            raise ValueError(f"unresolved grant type {name}")
        kind, body = declarations[name]
        if kind == "struct":
            field_list(body, name)
        else:
            remaining = body.strip()
            while remaining:
                match = re.match(r"([A-Za-z_]\w*)\s*(?:\{([^{}]*)\})?\s*,", remaining)
                if not match:
                    raise ValueError(f"unsupported grant variant in {name}")
                variant, fields = match.groups()
                rows.append(f"{name}.{variant}:variant")
                if fields is not None:
                    field_list(fields, f"{name}.{variant}")
                remaining = remaining[match.end():].strip()
    if len(rows) != len(set(rows)):
        raise ValueError("duplicate grant fields")
    return sorted(rows)


def check(root):
    actual = inventory((root / "crates/maknae-proto/src/mutation.rs").read_text())
    expected = []
    for line in (root / "ci/gates/mutation-disclosure-manifest.txt").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 3 or parts[0] != "always" or not parts[2].strip():
            raise ValueError("grant disclosure row needs always, field/type, and rationale")
        expected.append(parts[1])
    if sorted(expected) != actual:
        missing = sorted(set(actual) - set(expected))
        stale = sorted(set(expected) - set(actual))
        raise ValueError(f"mutation grant disclosure inventory differs; undecided={missing}, stale={stale}")
    print(f"mutation-disclosure: {len(actual)} grant fields/variants decided")


if __name__ == "__main__":
    try:
        check(Path(sys.argv[1] if len(sys.argv) > 1 else "."))
    except (OSError, ValueError) as error:
        print(f"FAIL: {error}")
        sys.exit(1)
