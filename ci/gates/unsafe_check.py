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
MIN_EDITION = 2021
TOKEN = re.compile(r"\bunsafe\b")
CHAR_LITERAL = re.compile(
    r"'(?:\\(?:u\{[0-9a-fA-F_]{1,6}\}|x[0-9a-fA-F]{2}|.)|[^\\'])'", re.DOTALL
)
RAW_START = re.compile(r'[bc]?r(#*)"')
MACRO_EXPORT = re.compile(r"\bmacro_export\b")
MACRO_RULES = re.compile(r"\bmacro_rules\s*!")
INNER_ATTR = re.compile(r"#\s*!")
UNSAFE_CODE = re.compile(r"\bunsafe_code\b")
LOOSENING = re.compile(r"\b(?:allow|expect|warn)\b")
MOD_ITEM = re.compile(r"\s*(?:pub\s*(?:\([^)]*\))?\s*)?mod\b")
ATTR_START = re.compile(r"#\s*!?\s*\[")
PATH_ATTR = re.compile(r"\s*path\s*=")
CFG_ATTR = re.compile(r"\s*cfg_attr\b")
CFG_ATTR_PATH = re.compile(r"[(,]\s*path\s*=")
INCLUDE = re.compile(r"\binclude\b")
RAW_PATH = re.compile(r"\br#path\b")
PUB_REEXPORT = re.compile(r"\bpub\s+(?:use|extern\s+crate)\b[^;]*")
SYS_TOKEN = re.compile(r"\bmaknae_sys\b")
CARGO_MANIFEST = re.compile(r"(?:^|/)Cargo\.toml$", re.IGNORECASE)
CARGO_CONFIG = re.compile(r"(?:^|/)\.cargo/config(?:\.toml)?$", re.IGNORECASE)
BUILD_DOORS = {"rustc", "rustc-wrapper", "rustc-workspace-wrapper"}
ENV_DOORS = {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC"}
UNREADABLE = (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, json.JSONDecodeError)


def is_ident(ch):
    return ch.isalnum() or ch == "_"


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
                raw = None if i > 0 and is_ident(source[i - 1]) else RAW_START.match(source, i)
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


def attributes(masked):
    for match in ATTR_START.finditer(masked):
        depth, i = 1, match.end()
        while i < len(masked) and depth:
            if masked[i] == "[": depth += 1
            elif masked[i] == "]": depth -= 1
            i += 1
        yield match.start(), masked[match.end():i], i


def next_item_is_mod(masked, end):
    i = end
    while True:
        while i < len(masked) and masked[i].isspace():
            i += 1
        outer = ATTR_START.match(masked, i)
        if not outer or INNER_ATTR.match(masked, i):
            break
        depth, i = 1, outer.end()
        while i < len(masked) and depth:
            if masked[i] == "[": depth += 1
            elif masked[i] == "]": depth -= 1
            i += 1
    return MOD_ITEM.match(masked, i) is not None


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


def lint_flag(token):
    return token.startswith(("--cap-lints", "-A", "--allow", "-C", "--config"))


def config_doors(parsed):
    found = []
    if "include" in parsed:
        found.append("sets include; an included config is not checked")
    build = parsed.get("build")
    if isinstance(build, dict):
        for key in build:
            if key.replace("_", "-") in BUILD_DOORS:
                found.append(f"sets build.{key}")
    alias = parsed.get("alias")
    if isinstance(alias, dict):
        for name, value in alias.items():
            tokens = value.split() if isinstance(value, str) else [str(t) for t in value] if isinstance(value, list) else []
            for token in tokens:
                if lint_flag(token):
                    found.append(f"alias.{name} passes a refused flag ({token})")
    env = parsed.get("env")
    if isinstance(env, dict):
        for key in env:
            upper = key.upper()
            if upper in ENV_DOORS or upper.startswith("RUSTC_"):
                found.append(f"sets env.{key}")
    return found


def declares_proc_macro(manifest):
    lib = manifest.get("lib")
    if not isinstance(lib, dict):
        return False
    crate_types = lib.get("crate-type", lib.get("crate_type", []))
    return (
        lib.get("proc-macro") is True
        or lib.get("proc_macro") is True
        or (isinstance(crate_types, list) and "proc-macro" in crate_types)
    )


def manifest_source_paths(manifest):
    found = []
    lib = manifest.get("lib")
    if isinstance(lib, dict) and "path" in lib:
        found.append(("[lib]", lib["path"]))
    for table in ("bin", "test", "example", "bench"):
        entries = manifest.get(table)
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict) and "path" in entry:
                    found.append((f"[[{table}]] {entry.get('name', '?')}", entry["path"]))
    package = manifest.get("package")
    if isinstance(package, dict) and isinstance(package.get("build"), str):
        found.append(("package.build", package["build"]))
    return found


def load_toml(path, what, fails):
    try:
        return tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except UNREADABLE as e:
        fails.append(f"{what}: cannot be parsed ({e}); it was not checked")
        return None


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def main(argv):
    root = Path(argv[1]).resolve()
    sys_crate = argv[2]
    allow = set(argv[3].split())
    sys_label = f"crates/{sys_crate}/"
    try:
        packages = json.loads(Path(argv[4]).read_text(encoding="utf-8"))["packages"]
        tracked = [f for f in Path(argv[5]).read_text(encoding="utf-8").split("\0") if f]
    except (*UNREADABLE, KeyError) as e:
        print(f"FAIL: the cargo metadata or git listing cannot be parsed ({e}); nothing was examined")
        return 1
    if not packages:
        print("FAIL: cargo metadata resolved ZERO packages; nothing was examined")
        return 1
    files = [f for f in tracked if f.lower().endswith(".rs")]
    configs = [f for f in tracked if CARGO_CONFIG.search(f)]
    manifests = [f for f in tracked if CARGO_MANIFEST.search(f)]

    fails = []
    workspace = load_toml(root / "Cargo.toml", "root Cargo.toml", fails)
    if workspace is not None:
        ws_rust = workspace.get("workspace", {}).get("lints", {}).get("rust", {})
        if ws_rust.get("unsafe_code") != "forbid":
            fails.append('root Cargo.toml: [workspace.lints.rust] does not set unsafe_code = "forbid"')

    names = set()
    package_dirs = {}
    target_sources = []
    for pkg in packages:
        name = pkg["name"]
        names.add(name)
        manifest = Path(pkg["manifest_path"])
        try:
            package_dirs[name] = manifest.resolve().parent.relative_to(root).as_posix()
        except ValueError:
            pass
        parsed = load_toml(manifest, f"{name}: {manifest}", fails)
        lints = parsed.get("lints") if parsed is not None else None
        edition = str(pkg.get("edition", ""))
        if not edition.isdigit() or int(edition) < MIN_EDITION:
            fails.append(f"{name}: edition {edition} is below {MIN_EDITION}; the token scan lexes {MIN_EDITION} or later")
        for target in pkg.get("targets", []):
            target_sources.append((name, target.get("name"), target.get("src_path", "")))
            target_edition = str(target.get("edition", ""))
            if not target_edition.isdigit() or int(target_edition) < MIN_EDITION:
                fails.append(f"{name}: target {target.get('name')} edition {target_edition} is below {MIN_EDITION}; the token scan lexes {MIN_EDITION} or later")
            if "proc-macro" in target.get("kind", []):
                fails.append(f"{name}: target {target.get('name')} is a proc-macro; a macro would carry unsafe past unsafe_code (ADR-0027)")
        if name == sys_crate:
            if manifest.resolve() != (root / sys_label / "Cargo.toml").resolve():
                fails.append(f"{sys_crate}: manifest is {manifest}, not {sys_label}Cargo.toml")
            if parsed is not None and lints != SYS_LINTS:
                fails.append(f"{sys_crate}: [lints] must be exactly {SYS_LINTS}, found {lints}")
        elif parsed is not None and lints != {"workspace": True}:
            fails.append(f"{name}: does not declare [lints] workspace = true (found {lints})")
        for dep in pkg["dependencies"]:
            if dep["name"] == sys_crate and name not in allow:
                fails.append(f"{name}: depends on {sys_crate} but is not in SYS_CONSUMER_ALLOW {sorted(allow)}")
    if sys_crate not in names:
        fails.append(f"{sys_crate}: not a workspace member")

    sys_dir = package_dirs.get(sys_crate)
    if sys_dir is not None:
        for name, rel in package_dirs.items():
            if name != sys_crate and (rel + "/").startswith(sys_dir + "/"):
                fails.append(f"{name}: workspace member nested under {sys_dir}/; only {sys_crate} may live there")

    def owner(rel):
        best, best_len = None, -1
        for name, pdir in package_dirs.items():
            if (pdir in ("", ".") or rel.startswith(pdir + "/")) and len(pdir) > best_len:
                best, best_len = name, len(pdir)
        return best

    for rel in manifests:
        parsed = load_toml(root / rel, rel, fails)
        if parsed is not None and declares_proc_macro(parsed):
            fails.append(f"{rel}: declares a proc-macro crate; no tracked crate may be one, member or not (ADR-0027)")
        for where, source in manifest_source_paths(parsed or {}):
            if not str(source).lower().endswith(".rs"):
                fails.append(f"{rel}: {where} path {source} is not a .rs file; the scan reads only .rs files (ADR-0027)")

    for rel in configs:
        parsed = load_toml(root / rel, rel, fails)
        if parsed is not None:
            for finding in config_findings(parsed, "") + config_doors(parsed):
                fails.append(f"{rel}: {finding}; lint levels come only from manifests (ADR-0027)")

    scanned = 0
    examined = set()
    for rel in files:
        try:
            masked = mask_noncode((root / rel).read_text(encoding="utf-8"))
            examined.add((root / rel).resolve())
        except (OSError, UnicodeDecodeError) as e:
            fails.append(f"{rel}: cannot be read ({e}); it was not scanned")
            continue
        rel_owner = owner(rel)
        for match in MACRO_EXPORT.finditer(masked):
            fails.append(f"{rel}:{line_of(masked, match.start())}: macro_export in {rel_owner or 'the repository'}; an exported macro's unsafe escapes forbid in every consumer (ADR-0027)")
        for start, body, end in attributes(masked):
            if rel_owner == sys_crate and INNER_ATTR.match(masked, start) and UNSAFE_CODE.search(body) and LOOSENING.search(body):
                fails.append(f"{rel}:{line_of(masked, start)}: inner attribute loosens unsafe_code in {sys_crate}; only non-module items may allow it (ADR-0027)")
            elif rel_owner == sys_crate and UNSAFE_CODE.search(body) and LOOSENING.search(body) and next_item_is_mod(masked, end):
                fails.append(f"{rel}:{line_of(masked, start)}: module-level allow of unsafe_code in {sys_crate}; only non-module items may allow it (ADR-0027)")
            if "$" in body:
                fails.append(f"{rel}:{line_of(masked, start)}: macro fragment in attribute position; it can spell #[path] (ADR-0027)")
            if PATH_ATTR.match(body) or (CFG_ATTR.match(body) and CFG_ATTR_PATH.search(body)):
                fails.append(f"{rel}:{line_of(masked, start)}: #[path] attribute; it compiles a file the scan does not list (ADR-0027)")
        for match in RAW_PATH.finditer(masked):
            fails.append(f"{rel}:{line_of(masked, match.start())}: #[path] attribute (r#path); it compiles a file the scan does not list (ADR-0027)")
        for match in INCLUDE.finditer(masked):
            fails.append(f"{rel}:{line_of(masked, match.start())}: include identifier; include! or a route to it compiles a file the scan does not list (ADR-0027)")
        for match in PUB_REEXPORT.finditer(masked):
            if SYS_TOKEN.search(match.group(0)):
                fails.append(f"{rel}:{line_of(masked, match.start())}: re-exports maknae_sys past SYS_CONSUMER_ALLOW (ADR-0027)")
        if rel_owner == sys_crate:
            for match in MACRO_RULES.finditer(masked):
                fails.append(f"{rel}:{line_of(masked, match.start())}: macro_rules! in {sys_crate}; it may define no macro (ADR-0027)")
            continue
        scanned += 1
        for match in TOKEN.finditer(masked):
            fails.append(f"{rel}:{line_of(masked, match.start())}: unsafe outside {sys_label}")
    if scanned == 0:
        fails.append(f"git ls-files listed ZERO .rs files outside {sys_label}; no source was examined")
    for name, target, source in target_sources:
        if Path(source).resolve() not in examined:
            fails.append(f"{name}: target {target} source {source} is not a scanned .rs file (ADR-0027)")

    for f in fails:
        print(f"FAIL: {f}")
    if fails:
        return 1
    print(f"unsafe-confinement: ok (packages: {len(packages)}, source files: {scanned})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
