#!/usr/bin/env python3
"""Derive, from source alone, the production code a mutation build compiles on
only one of {linux, macos}, and check that the native mutation filter
(mutation-platform.sh) excludes exactly that code on exactly the inactive host.

    platform-gated.py check ROOT    exit 1 naming every violation
    platform-gated.py list ROOT     print the derived set
"""
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import NamedTuple

PLATFORMS = ("linux", "macos")
UNAME = {"linux": "Linux", "macos": "Darwin"}
SYSCALL = "crates/maknae-io/src/syscall.rs"
REQUIRED = ("linux_fd_path", "macos_fd_path", "crates/maknae-sys/src/macos.rs")
MULTI_PUNCT = ("::", "->", "=>", "==", "!=", "<=", ">=", "&&", "||", "..")
CHAR_LITERAL = re.compile(r"b?'(?:\\(?:u\{[0-9a-fA-F_]{1,6}\}|x[0-9a-fA-F]{2}|.)|[^\\'\n])'")
RAW_STRING = re.compile(r'[bc]?r(#*)"')
PLAIN_STRING = re.compile(r'[bc]?"')
IDENT = re.compile(r"(?:r#)?[A-Za-z_][A-Za-z0-9_]*")
NUMBER = re.compile(r"[0-9][0-9A-Za-z_]*")
LIFETIME = re.compile(r"'[A-Za-z_][A-Za-z0-9_]*")
QUALIFIERS = {"const", "async", "unsafe", "default", "safe"}
BLOCK_ITEMS = {"impl", "trait"}
NESTING = {"fn", "mod", "impl", "trait"}
TEST_ATTRS = {"test", "tokio::test", "test_case"}
PARSED_KINDS = {"lib", "rlib", "bin"}
UNPARSED_KINDS = {"test", "bench", "example", "custom-build"}


class GateError(Exception):
    pass


class Tok(NamedTuple):
    kind: str
    text: str
    line: int


class Gated(NamedTuple):
    crate: str
    file: str
    line: int
    kind: str
    name: str
    active: frozenset
    in_impl: bool = False
    has_items: bool = False


def synthetic(name):
    return (f"replace {name} -> T with x", f"replace {name} with ()", f"replace + with - in {name}")


def lex(source, where):
    toks, i, line, n = [], 0, 1, len(source)
    while i < n:
        ch = source[i]
        if ch == "\n":
            line += 1; i += 1
        elif ch.isspace():
            i += 1
        elif source.startswith("//", i):
            end = source.find("\n", i)
            i = n if end < 0 else end
        elif source.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if source.startswith("/*", i):
                    depth += 1; i += 2
                elif source.startswith("*/", i):
                    depth -= 1; i += 2
                else:
                    line += source[i] == "\n"; i += 1
            if depth:
                raise GateError(f"{where}:{line}: unterminated block comment")
        elif (raw := RAW_STRING.match(source, i)):
            close = '"' + raw.group(1)
            end = source.find(close, raw.end())
            if end < 0:
                raise GateError(f"{where}:{line}: unterminated raw string")
            toks.append(Tok("str", source[raw.end():end], line))
            line += source.count("\n", i, end); i = end + len(close)
        elif (plain := PLAIN_STRING.match(source, i)):
            j = plain.end()
            while j < n and source[j] != '"':
                j += 2 if source[j] == "\\" else 1
            if j >= n:
                raise GateError(f"{where}:{line}: unterminated string")
            toks.append(Tok("str", source[plain.end():j], line))
            line += source.count("\n", i, j); i = j + 1
        elif (char := CHAR_LITERAL.match(source, i)):
            toks.append(Tok("lit", char.group(0), line)); i = char.end()
        elif (life := LIFETIME.match(source, i)):
            toks.append(Tok("lit", life.group(0), line)); i = life.end()
        elif (ident := IDENT.match(source, i)):
            toks.append(Tok("ident", ident.group(0), line)); i = ident.end()
        elif (num := NUMBER.match(source, i)):
            toks.append(Tok("lit", num.group(0), line)); i = num.end()
        else:
            punct = next((p for p in MULTI_PUNCT if source.startswith(p, i)), ch)
            toks.append(Tok("punct", punct, line)); i += len(punct)
    return toks


def matching(toks, i, file):
    pairs = {"(": ")", "[": "]", "{": "}"}
    opener = toks[i]
    stack = [pairs[opener.text]]
    i += 1
    while i < len(toks) and stack:
        t = toks[i]
        if t.kind == "punct":
            if t.text in pairs:
                stack.append(pairs[t.text])
            elif t.text in (")", "]", "}"):
                if t.text != stack.pop():
                    raise GateError(f"{file}:{t.line}: mismatched '{t.text}'")
        i += 1
    if stack:
        raise GateError(f"{file}:{opener.line}: unbalanced '{opener.text}'")
    return i


def is_punct(toks, i, text):
    return i < len(toks) and toks[i].kind == "punct" and toks[i].text == text


def is_ident(toks, i, text=None):
    return i < len(toks) and toks[i].kind == "ident" and (text is None or toks[i].text == text)


def after_prefix(toks, i, file):
    if is_ident(toks, i, "pub"):
        i += 1
        if is_punct(toks, i, "("):
            i = matching(toks, i, file)
    while is_ident(toks, i) and (toks[i].text in QUALIFIERS or toks[i].text == "extern"):
        if toks[i].text == "extern" and not (is_ident(toks, i + 1, "fn")
                                             or (toks[i + 1].kind == "str" and is_ident(toks, i + 2))):
            break
        i += 2 if toks[i].text == "extern" and toks[i + 1].kind == "str" else 1
    return i


def top_level_args(toks):
    args, depth = [[]], 0
    for t in toks:
        if t.kind == "punct" and t.text in ("(", "[", "{"):
            depth += 1
        elif t.kind == "punct" and t.text in (")", "]", "}"):
            depth -= 1
        if depth == 0 and t.text == ",":
            args.append([])
        else:
            args[-1].append(t.text)
    return args


def gates(body):
    texts = [t.text for t in body]
    if texts[:2] == ["cfg", "("]:
        return True
    if texts[:2] == ["cfg_attr", "("]:
        return any(arg[:2] == ["cfg", "("] for arg in top_level_args(body[2:-1])[1:])
    return False


def attribute(body, where):
    path = []
    for t in body:
        if t.kind != "ident" and t.text != "::":
            break
        path.append(t.text)
    path = "".join(path)
    texts = [t.text for t in body]
    if path == "cfg_attr" and gates(body):
        raise GateError(f"{where}: cfg inside cfg_attr is not evaluated; write the cfg as its own attribute")
    if path == "cfg_attr" and any(arg[:2] == ["path", "="] for arg in top_level_args(body[2:-1])[1:]):
        raise GateError(f"{where}: path inside cfg_attr is not followed")
    if path.endswith("::test") and path not in TEST_ATTRS:
        raise GateError(f"{where}: unknown test attribute `{path}`")
    cfg = body[2:-1] if texts[:2] == ["cfg", "("] and texts[-1] == ")" else None
    return cfg, path in TEST_ATTRS


def parse_cfg(toks, file, line):
    where = f"{file}:{line}"

    def one(i):
        if not is_ident(toks, i):
            raise GateError(f"{where}: malformed cfg predicate")
        name = toks[i].text
        if name in ("all", "any", "not") and is_punct(toks, i + 1, "("):
            args, i, end = [], i + 2, matching(toks, i + 1, file) - 1
            while i < end:
                node, i = one(i)
                args.append(node)
                if is_punct(toks, i, ","):
                    i += 1
                elif i != end:
                    raise GateError(f"{where}: malformed cfg predicate")
            if name == "not" and len(args) != 1:
                raise GateError(f"{where}: not() takes one predicate")
            return (name, args), end + 1
        if is_punct(toks, i + 1, "=") and i + 2 < len(toks) and toks[i + 2].kind == "str":
            return ("kv", name, toks[i + 2].text), i + 3
        return ("flag", name), i + 1
    node, end = one(0)
    if end != len(toks):
        raise GateError(f"{where}: malformed cfg predicate")
    return node


def render(node):
    if node[0] == "kv":
        return f'{node[1]} = "{node[2]}"'
    if node[0] == "flag":
        return node[1]
    return f"{node[0]}({', '.join(render(a) for a in node[1])})"


def evaluate(node, platform, test, features, where):
    kind = node[0]
    if kind in ("all", "any", "not"):
        values = [evaluate(a, platform, test, features, where) for a in node[1]]
        return all(values) if kind == "all" else any(values) if kind == "any" else not values[0]
    if kind == "flag":
        if node[1] == "test":
            return test
        if node[1] == "unix":
            return True
    elif node[1] == "target_os" and node[2] in PLATFORMS:
        return node[2] == platform
    elif node[1] == "target_vendor" and node[2] == "apple":
        return platform == "macos"
    elif node[1] == "feature":
        return node[2] in features
    raise GateError(f"{where}: unsupported cfg predicate `{render(node)}`")


class Ctx(NamedTuple):
    crate: str
    file: str
    mod_dir: Path
    conds: tuple
    in_impl: bool
    gated_file: bool
    scope: tuple = ()


class Deriver:
    def __init__(self, root, features, excluded):
        self.root, self.features, self.excluded = root, features, excluded
        self.items = []

    def rel(self, path):
        return path.resolve().relative_to(self.root).as_posix()

    def status(self, conds, where):
        def active(test):
            return frozenset(p for p in PLATFORMS
                             if all(evaluate(c, p, test, self.features, where) for c in conds))
        in_test, outside_test = active(True), active(False)
        return in_test | outside_test, bool(in_test) and not outside_test

    def read_attrs(self, toks, i, ctx):
        cfgs, test, path = [], False, False
        while is_punct(toks, i, "#") and not is_punct(toks, i + 1, "!") and is_punct(toks, i + 1, "["):
            end = matching(toks, i + 1, ctx.file)
            body = toks[i + 2:end - 1]
            cfg, is_test = attribute(body, f"{ctx.file}:{toks[i].line}")
            if cfg is not None:
                cfgs.append(parse_cfg(cfg, ctx.file, toks[i].line))
            test |= is_test
            if [t.text for t in body[:2]] == ["path", "="]:
                path = True
            i = end
        return cfgs, test, path, i

    def module(self, toks, i, end, ctx):
        while is_punct(toks, i, "#") and is_punct(toks, i + 1, "!") and is_punct(toks, i + 2, "["):
            close = matching(toks, i + 2, ctx.file)
            cfg, _ = attribute(toks[i + 3:close - 1], f"{ctx.file}:{toks[i].line}")
            if cfg is not None:
                ctx = ctx._replace(conds=ctx.conds + (parse_cfg(cfg, ctx.file, toks[i].line),))
            i = close
        if self.status(ctx.conds, f"{ctx.file}:1")[1]:
            return False
        has_items = False
        while i < end:
            if is_punct(toks, i, ";"):
                i += 1
                continue
            has_items |= self.item(toks, i, end, ctx)
            i = self.item_end
        return has_items

    def item(self, toks, i, end, ctx):
        line = toks[i].line
        if is_punct(toks, i, "#") and is_punct(toks, i + 1, "!"):
            self.item_end = matching(toks, i + 2, ctx.file)
            return False
        cfgs, test, path, i = self.read_attrs(toks, i, ctx)
        where = f"{ctx.file}:{line}"
        conds = ctx.conds + tuple(cfgs)
        active, test_only = self.status(conds, where)
        test_only |= test
        i = after_prefix(toks, i, ctx.file)
        keyword = toks[i].text if is_ident(toks, i) else None
        gated = active != frozenset(PLATFORMS) and not test_only
        kept = not test_only and ctx.file not in self.excluded and not ctx.gated_file
        if keyword == "fn":
            name = "::".join(ctx.scope + (toks[i + 1].text,))
            body = self.skip(toks, i, end, True, ctx)
            if kept and gated:
                self.no_nested(toks, i + 2, self.item_end, ctx, f"fn {name}")
                if body:
                    self.items.append(Gated(ctx.crate, ctx.file, toks[i + 1].line, "fn", name, active, ctx.in_impl))
            return not test_only
        if keyword == "mod":
            name = toks[i + 1].text
            if is_punct(toks, i + 2, ";"):
                if path:
                    raise GateError(f"{where}: #[path] on mod {name} is not followed")
                self.item_end = i + 3
                if test_only:
                    return False
                child = self.resolve(ctx, name, where)
                rel = self.rel(child)
                child_ctx = ctx._replace(file=rel, mod_dir=child.parent if child.name == "mod.rs"
                                         else child.parent / child.stem, conds=conds, in_impl=False,
                                         gated_file=ctx.gated_file or gated, scope=())
                if gated and rel not in self.excluded:
                    self.items.append(Gated(ctx.crate, rel, 1, "mod-file", name, active))
                self.parse_file(child, child_ctx)
                self.item_end = i + 3
                return True
            if is_punct(toks, i + 2, "{"):
                close = matching(toks, i + 2, ctx.file)
                self.item_end = close
                if test_only:
                    return False
                inner = ctx._replace(mod_dir=ctx.mod_dir / name, conds=conds, scope=ctx.scope + (name,))
                has_items = self.module(toks, i + 3, close - 1, inner)
                self.item_end = close
                if kept and gated:
                    self.items.append(Gated(ctx.crate, ctx.file, line, "inline-mod", name, active, has_items=has_items))
                return True
        if keyword in BLOCK_ITEMS:
            j = i
            while j < end and not is_punct(toks, j, "{"):
                if is_punct(toks, j, ";"):
                    self.item_end = j + 1
                    return not test_only
                j += 1
            close = matching(toks, j, ctx.file)
            if test_only:
                self.item_end = close
                return False
            inner = ctx._replace(conds=conds, in_impl=True)
            has_items, k = False, j + 1
            while k < close - 1:
                if is_punct(toks, k, ";"):
                    k += 1
                    continue
                has_items |= self.item(toks, k, close - 1, inner)
                k = self.item_end
            self.item_end = close
            if kept and gated:
                header = " ".join(t.text for t in toks[i:j])
                self.items.append(Gated(ctx.crate, ctx.file, line, "impl", header, active, has_items=has_items))
            return True
        if keyword in ("struct", "enum", "union"):
            self.generics(toks, i, end, ctx)
        foreign = keyword == "extern"
        braced = keyword in ("struct", "enum", "union", "extern") or is_punct(toks, i + 1, "!")
        self.skip(toks, i, end, braced, ctx, scan=not foreign)
        if kept and gated and not foreign:
            self.no_nested(toks, i, self.item_end, ctx, f"{keyword} item")
        return False

    def generics(self, toks, i, end, ctx):
        depth, k = 0, i + 2
        while k < end and not (depth == 0 and toks[k].text in ("{", ";", "(")):
            if toks[k].text == "<":
                depth += 1
            elif toks[k].text == ">":
                depth -= 1
            elif toks[k].text == "{":
                raise GateError(f"{ctx.file}:{toks[k].line}: '{{' inside the generics of "
                                f"{toks[i].text} {toks[i + 1].text}; the item's extent is not derivable")
            elif toks[k].text in ("(", "["):
                k = matching(toks, k, ctx.file)
                continue
            k += 1

    def nested(self, toks, i, end, file):
        at_start = True
        while i < end:
            if at_start:
                start, gated = i, False
                while is_punct(toks, i, "#") and (is_punct(toks, i + 1, "[")
                                                   or (is_punct(toks, i + 1, "!") and is_punct(toks, i + 2, "["))):
                    opener = i + 1 if is_punct(toks, i + 1, "[") else i + 2
                    close = matching(toks, opener, file)
                    gated |= gates(toks[opener + 1:close - 1])
                    i = close
                k = after_prefix(toks, i, file)
                if k < end and is_ident(toks, k) and toks[k].text in NESTING:
                    yield toks[k].text, gated, toks[start].line
                at_start = False
                continue
            at_start = toks[i].kind == "punct" and toks[i].text in ("{", "}", ";")
            i += 1

    def no_nested(self, toks, i, end, ctx, owner):
        for keyword, _, line in self.nested(toks, i, end, ctx.file):
            raise GateError(f"{ctx.file}:{line}: {keyword} inside platform-gated {owner}; its mutants are "
                            "named with a path, which the filter cannot match")

    def skip(self, toks, i, end, braced, ctx, scan=True):
        start = toks[i].line
        while i < end:
            t = toks[i]
            if t.kind == "punct":
                if t.text == ";":
                    self.item_end = i + 1
                    return False
                if t.text in ("(", "[", "{"):
                    close = matching(toks, i, ctx.file)
                    for keyword, gated, line in self.nested(toks, i + 1, close - 1, ctx.file) if scan else ():
                        if gated:
                            raise GateError(f"{ctx.file}:{line}: cfg-gated {keyword} inside a body or initializer; "
                                            "its mutants are not derivable by name — hoist it to module level")
                    if t.text == "{" and braced:
                        self.item_end = close
                        return True
                    i = close
                    continue
            i += 1
        raise GateError(f"{ctx.file}:{start}: item runs off the end of its module")

    def resolve(self, ctx, name, where):
        for candidate in (ctx.mod_dir / f"{name}.rs", ctx.mod_dir / name / "mod.rs"):
            if candidate.is_file():
                return candidate
        raise GateError(f"{where}: cannot resolve mod {name} under {ctx.mod_dir}")

    def parse_file(self, path, ctx):
        toks = lex(path.read_text(), ctx.file)
        self.module(toks, 0, len(toks), ctx)


def tiers(root):
    return tomllib.loads((root / "coverage-tiers.toml").read_text())["t1"]


def excluded_files(root):
    globs = tomllib.loads((root / ".cargo/mutants.toml").read_text()).get("exclude_globs", [])
    for glob in globs:
        if any(c in glob for c in "*?[]{}!"):
            raise GateError(f".cargo/mutants.toml: exclude_globs entry {glob!r} is a pattern; "
                            "extend the matcher deliberately")
    return set(globs)


def build_features(table, requested):
    pending = list(requested) + (["default"] if "default" in table else [])
    enabled = set()
    while pending:
        feature = pending.pop()
        if feature in enabled:
            continue
        enabled.add(feature)
        for entry in table.get(feature, []):
            head = entry.split("/", 1)[0]
            if entry.startswith("dep:") or head.endswith("?"):
                continue
            if "/" not in entry or head in table:
                pending.append(head)
    return enabled


def derive(root):
    root = Path(root).resolve()
    t1 = tiers(root)
    crates = t1.get("mutants_crates") or []
    features = t1.get("mutants_features") or {}
    meta = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"], cwd=root, text=True))
    excluded = excluded_files(root)
    items = []
    for package in meta["packages"]:
        if package["name"] not in crates:
            continue
        enabled = build_features(package["features"], features.get(package["name"], []))
        deriver = Deriver(root, enabled, excluded)
        for target in package["targets"]:
            kinds = set(target["kind"])
            if kinds <= UNPARSED_KINDS:
                continue
            if not kinds <= PARSED_KINDS:
                raise GateError(f"{package['name']}: target {target['name']} has kind "
                                f"{','.join(sorted(kinds - PARSED_KINDS))}, which this gate does not model")
            src = Path(target["src_path"])
            ctx = Ctx(package["name"], deriver.rel(src), src.parent, (), False, False)
            deriver.parse_file(src, ctx)
        items.extend(deriver.items)
    missing = set(crates) - {p["name"] for p in meta["packages"]}
    if missing:
        raise GateError(f"mutants_crates names unknown packages: {sorted(missing)}")
    return sorted(set(items), key=lambda g: (g.crate, g.file, g.line, g.kind, g.name))


def filtered(root):
    lines = (Path(root) / "ci/gates/coverage-tiers.sh").read_text().splitlines()
    call = [n for n, text in enumerate(lines) if "mutation-platform.sh" in text and not text.lstrip().startswith("#")]
    if len(call) != 1:
        raise GateError("coverage-tiers.sh: expected exactly one mutation-platform.sh call")
    guard = next((lines[n] for n in range(call[0], -1, -1) if re.match(r"\s*if \[", lines[n])), "")
    crates = set(re.findall(r'\[ "\$cname" = "([^"]+)" \]', guard))
    if not crates:
        raise GateError("coverage-tiers.sh: no crate list guards the mutation-platform.sh call")
    return crates


def filter_lists(root):
    script = (Path(root) / "ci/gates/mutation-platform.sh").read_text()
    lists = {}
    for platform, uname in UNAME.items():
        m = re.search(uname + r"\)\s*absent='([^']*)'\s*inactive_files='([^']*)'\s*(?:#[^\n]*\n\s*)*"
                      r"root_only='([^']*)';;", script)
        if not m:
            raise GateError(f"mutation-platform.sh: no {uname} absent/inactive_files/root_only arm")
        files = set()
        for alt in filter(None, m.group(2).split("|")):
            path = re.fullmatch(r"\^(.+):", alt)
            if not path:
                raise GateError(f"mutation-platform.sh: unrecognised inactive_files entry {alt!r}")
            files.add(path.group(1).replace("\\.", "."))
        root_only = set(filter(None, m.group(3).split("|")))
        for alt in root_only:
            if not re.fullmatch(r"\^crates/[^:]+\\\.rs:\[0-9\]\+:\[0-9\]\+: replace [A-Za-z_][A-Za-z0-9_]* -> .+\$", alt):
                raise GateError(f"mutation-platform.sh: root_only entry {alt!r} is not one anchored mutant")
        lists[platform] = (set(filter(None, m.group(1).split("|"))), files, root_only)
    return lists


def emitted(root):
    script = Path(root) / "ci/gates/mutation-platform.sh"
    return {p: subprocess.check_output(["bash", str(script), UNAME[p]], text=True).strip() for p in PLATFORMS}


def check(root):
    items = derive(root)
    crates, lists, regex = filtered(root), filter_lists(root), emitted(root)
    problems = []
    for g in items:
        at = f"{g.file}:{g.line}: {g.kind} {g.name}"
        inactive = [p for p in PLATFORMS if p not in g.active]
        if g.crate not in crates:
            problems.append(f"{at} is platform-gated in {g.crate}, which the native mutation filter does not cover")
        if g.kind == "fn":
            if g.in_impl:
                problems.append(f"{at} is platform-gated inside an impl; its mutants are named "
                                "<impl …>::name, which the filter cannot match — hoist it to a free fn in syscall.rs")
                continue
            if "::" in g.name:
                problems.append(f"{at} is platform-gated below the top level of its file; its mutants are "
                                "named with the module path, which the filter cannot match")
                continue
            if g.file != SYSCALL:
                problems.append(f"{at} is platform-gated outside {SYSCALL}; move it to syscall.rs or gate its module file")
                continue
            for p in PLATFORMS:
                listed = g.name in lists[p][0]
                if p in inactive and not listed:
                    problems.append(f"{at} is inactive on {p} but missing from mutation-platform.sh's {UNAME[p]} absent list")
                if p not in inactive and listed:
                    problems.append(f"{at} is active on {p} but excluded by mutation-platform.sh's {UNAME[p]} absent list")
        elif g.kind == "mod-file":
            for p in PLATFORMS:
                listed = g.file in lists[p][1]
                if p in inactive and not listed:
                    problems.append(f"{at} is inactive on {p} but missing from mutation-platform.sh's {UNAME[p]} inactive_files")
                if p not in inactive and listed:
                    problems.append(f"{at} is active on {p} but excluded by mutation-platform.sh's {UNAME[p]} inactive_files")
        elif g.has_items:
            problems.append(f"{at} is a platform-gated block containing items; hoist each fn into a uniquely named fn")
        if g.kind == "mod-file" or (g.kind == "fn" and g.file == SYSCALL and not g.in_impl and "::" not in g.name):
            if g.kind == "fn":
                near = f"{SYSCALL}:1:1: replace match guard a == {g.name} with true in {g.name}_neighbour"
                for p in PLATFORMS:
                    if re.search(regex[p], near):
                        problems.append(f"{near} is excluded on {p}; the filter matches more than the fn's own mutants")
            for shape in synthetic(g.name if g.kind == "fn" else "f"):
                line = f"{g.file}:1:1: {shape}"
                for p in PLATFORMS:
                    excluded = re.search(regex[p], line) is not None
                    if p in inactive and not excluded:
                        problems.append(f"{line} is not excluded on {p} by the emitted {UNAME[p]} filter")
                    if p not in inactive and excluded:
                        problems.append(f"{line} is excluded on {p}, where it is active")
    for p in PLATFORMS:
        fns = {g.name for g in items if g.kind == "fn" and g.file == SYSCALL and p not in g.active}
        files = {g.file for g in items if g.kind == "mod-file" and p not in g.active}
        for name in sorted(lists[p][0] - fns):
            problems.append(f"mutation-platform.sh's {UNAME[p]} absent list names {name}, "
                            f"which is not a platform-gated fn inactive on {p}")
        for file in sorted(lists[p][1] - files):
            problems.append(f"mutation-platform.sh's {UNAME[p]} inactive_files names {file}, "
                            f"which is not a platform-gated module file inactive on {p}")
    names = {g.name for g in items if g.kind == "fn"} | {g.file for g in items if g.kind == "mod-file"}
    for required in REQUIRED:
        if required not in names:
            problems.append(f"derived set lacks {required}; the parser is broken, not the tree")
    return items, problems


def show(g):
    active = ",".join(sorted(g.active)) or "none"
    return f"{g.crate}\t{g.file}:{g.line}\t{g.kind}\t{g.name}\tactive={active}"


def main(argv):
    if len(argv) != 3 or argv[1] not in ("check", "list"):
        print(f"usage: {argv[0]} check|list ROOT", file=sys.stderr)
        return 2
    try:
        if argv[1] == "list":
            for g in derive(argv[2]):
                print(show(g))
            return 0
        items, problems = check(argv[2])
    except (GateError, OSError, subprocess.CalledProcessError, tomllib.TOMLDecodeError, KeyError) as e:
        print(f"FAIL: platform-gated: {e}")
        return 1
    for problem in problems:
        print(f"FAIL: {problem}")
    if problems:
        return 1
    print(f"PASS: platform-gated: {len(items)} gated items, each filtered on exactly its inactive platforms")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
