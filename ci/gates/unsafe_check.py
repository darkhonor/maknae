#!/usr/bin/env python3
import json
import re
import sys
import tomllib
from pathlib import Path

SYS_LINTS = {
    "rust": {"unsafe_code": "deny", "unsafe_op_in_unsafe_fn": "forbid"},
    "clippy": {"undocumented_unsafe_blocks": "forbid", "multiple_unsafe_ops_per_block": "forbid"},
}
TOKEN = re.compile(r"\bunsafe\b")
CHAR_LITERAL = re.compile(
    r"'(?:\\(?:u\{[0-9a-fA-F_]{1,6}\}|x[0-9a-fA-F]{2}|.)|[^\\'])'", re.DOTALL
)
RAW_START = re.compile(r'r(#*)"')
MACRO_EXPORT = re.compile(r"#\s*\[\s*macro_export\b")
UNREADABLE = (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, json.JSONDecodeError)


def mask_noncode(source):
    out = list(source)
    i, state, raw_hashes, depth = 0, "code", 0, 0
    while i < len(source):
        if state == "code":
            if source.startswith("//", i):
                out[i:i+2] = "  "; i += 2; state = "line"
            elif source.startswith("/*", i):
                out[i:i+2] = "  "; i += 2; state = "block"; depth = 1
            elif source[i] == '"':
                out[i] = " "; i += 1; state = "string"
            elif source[i] == "'" and CHAR_LITERAL.match(source, i):
                end = CHAR_LITERAL.match(source, i).end()
                for pos in range(i, end):
                    if source[pos] != "\n":
                        out[pos] = " "
                i = end
            else:
                raw = RAW_START.match(source, i)
                if raw:
                    raw_hashes = len(raw.group(1))
                    width = raw.end() - i
                    out[i:i+width] = " " * width
                    i += width; state = "raw"
                else:
                    i += 1
        elif state == "line":
            if source[i] == "\n": state = "code"
            else: out[i] = " "
            i += 1
        elif state == "block":
            if source.startswith("/*", i):
                out[i:i+2] = "  "; i += 2; depth += 1
            elif source.startswith("*/", i):
                out[i:i+2] = "  "; i += 2; depth -= 1
                if depth == 0: state = "code"
            else:
                if source[i] != "\n": out[i] = " "
                i += 1
        elif state == "string":
            if source[i] == "\\":
                out[i] = " "; i += 1
                if i < len(source):
                    if source[i] != "\n": out[i] = " "
                    i += 1
            else:
                if source[i] == '"': state = "code"
                if source[i] != "\n": out[i] = " "
                i += 1
        else:
            end = '"' + ('#' * raw_hashes)
            if source.startswith(end, i):
                out[i:i+len(end)] = " " * len(end); i += len(end); state = "code"
            else:
                if source[i] != "\n": out[i] = " "
                i += 1
    return "".join(out)


def config_findings(value, where):
    found = []
    if isinstance(value, dict):
        for key, item in value.items():
            here = f"{where}.{key}" if where else key
            if key == "rustflags":
                found.append(f"sets rustflags ({here})")
            found.extend(config_findings(item, here))
    elif isinstance(value, list):
        for item in value:
            found.extend(config_findings(item, where))
    elif isinstance(value, str) and "--cap-lints" in value:
        found.append(f"passes --cap-lints ({where})")
    return found


def load_toml(path, what, fails):
    try:
        return tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except UNREADABLE as e:
        fails.append(f"{what}: cannot be parsed ({e}); it was not checked")
        return None


def main(argv):
    root = Path(argv[1])
    sys_crate = argv[2]
    allow = set(argv[3].split())
    sys_dir = f"crates/{sys_crate}/"
    try:
        packages = json.loads(Path(argv[4]).read_text(encoding="utf-8"))["packages"]
        files = [f for f in Path(argv[5]).read_text(encoding="utf-8").split("\0") if f]
        configs = [f for f in Path(argv[6]).read_text(encoding="utf-8").split("\0") if f]
    except (*UNREADABLE, KeyError) as e:
        print(f"FAIL: the cargo metadata or git listing cannot be parsed ({e}); nothing was examined")
        return 1
    if not packages:
        print("FAIL: cargo metadata resolved ZERO packages; nothing was examined")
        return 1
    if not files:
        print("FAIL: git ls-files listed ZERO .rs files; no source was examined")
        return 1

    fails = []
    workspace = load_toml(root / "Cargo.toml", "root Cargo.toml", fails)
    if workspace is not None:
        ws_rust = workspace.get("workspace", {}).get("lints", {}).get("rust", {})
        if ws_rust.get("unsafe_code") != "forbid":
            fails.append('root Cargo.toml: [workspace.lints.rust] does not set unsafe_code = "forbid"')

    names = set()
    for pkg in packages:
        name = pkg["name"]
        names.add(name)
        manifest = Path(pkg["manifest_path"])
        parsed = load_toml(manifest, f"{name}: {manifest}", fails)
        lints = parsed.get("lints") if parsed is not None else None
        if name == sys_crate:
            if manifest.resolve() != (root / sys_dir / "Cargo.toml").resolve():
                fails.append(f"{sys_crate}: manifest is {manifest}, not {sys_dir}Cargo.toml")
            if parsed is not None and lints != SYS_LINTS:
                fails.append(f"{sys_crate}: [lints] must be exactly {SYS_LINTS}, found {lints}")
            lib = (parsed or {}).get("lib", {})
            if lib.get("proc-macro") is True or lib.get("proc_macro") is True:
                fails.append(f"{sys_crate}: proc-macro = true; a macro would carry its unsafe past the safe surface (ADR-0027)")
        elif parsed is not None and lints != {"workspace": True}:
            fails.append(f"{name}: does not declare [lints] workspace = true (found {lints})")
        for dep in pkg["dependencies"]:
            if dep["name"] == sys_crate and name not in allow:
                fails.append(f"{name}: depends on {sys_crate} but is not in SYS_CONSUMER_ALLOW {sorted(allow)}")
    if sys_crate not in names:
        fails.append(f"{sys_crate}: not a workspace member")

    for rel in configs:
        parsed = load_toml(root / rel, rel, fails)
        if parsed is not None:
            for finding in config_findings(parsed, ""):
                fails.append(f"{rel}: {finding}; lint levels come only from manifests (ADR-0027)")

    scanned = 0
    for rel in files:
        if rel.startswith(sys_dir):
            try:
                masked = mask_noncode((root / rel).read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError) as e:
                fails.append(f"{rel}: cannot be read ({e}); it was not scanned")
                continue
            for match in MACRO_EXPORT.finditer(masked):
                line = masked.count("\n", 0, match.start()) + 1
                fails.append(f"{rel}:{line}: #[macro_export] in {sys_crate}; an exported macro would carry its unsafe past the safe surface (ADR-0027)")
            continue
        scanned += 1
        try:
            source = (root / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            fails.append(f"{rel}: cannot be read ({e}); it was not scanned")
            continue
        masked = mask_noncode(source)
        for match in TOKEN.finditer(masked):
            line = masked.count("\n", 0, match.start()) + 1
            fails.append(f"{rel}:{line}: unsafe outside {sys_dir}")

    for f in fails:
        print(f"FAIL: {f}")
    if fails:
        return 1
    print(f"unsafe-confinement: ok (packages: {len(packages)}, source files: {scanned})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
