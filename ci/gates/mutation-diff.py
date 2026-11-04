#!/usr/bin/env python3
"""Pure decisions for the PR-scoped mutation gate (#593). Python 3.11+, stdlib only."""
import importlib.util
import json
import os
from pathlib import Path
import posixpath
import re
import subprocess
import sys
import tomllib
import unicodedata

sys.dont_write_bytecode = True
GIT_ENV = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR",
           "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_LITERAL_PATHSPECS", "GIT_NOGLOB_PATHSPECS",
           "GIT_GLOB_PATHSPECS", "GIT_ICASE_PATHSPECS", "GIT_GRAFT_FILE")
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
BINARY = re.compile(r"^(?:Binary files .* differ|GIT binary patch)$")
ABSENT = re.compile(r"does not exist in|exists on disk, but not in")
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
PRODUCTION_LIB = frozenset(("lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"))
SCOPE_FILES = frozenset(("Cargo.toml", "coverage-tiers.toml", ".cargo/config", ".cargo/config.toml",
                         ".cargo/mutants.toml", ".config/nextest.toml", "rust-toolchain",
                         "rust-toolchain.toml", ".github/workflows/ci.yml", "ci/affected.py",
                         "ci/gates/coverage-tiers.sh", "ci/gates/mutation-oracle.sh",
                         "ci/gates/mutation-platform.sh", "ci/gates/mutation-diff.py",
                         "ci/gates/mutation-terminated.txt"))


class DiffError(Exception):
    pass


class ScopeError(Exception):
    pass


def split_lines(text):
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines


def read_diff(path):
    return Path(path).read_bytes().decode()


def header_path(line):
    rest = line[len("diff --git "):]
    size = (len(rest) - len("a/ b/")) // 2
    name = rest[2:2 + size]
    return name if size > 0 and rest == f"a/{name} b/{name}" else None


def changed_lines(diff_text):
    return parse(diff_text)[0]


def diff_paths(diff_text):
    return parse(diff_text)[1]


def parse(diff_text):
    lines = split_lines(diff_text)
    if not any(line.strip() for line in lines):
        return {}, set()
    if not any(line.startswith("diff --git ") for line in lines):
        raise DiffError("FAIL: non-empty diff with no 'diff --git' header")
    result = {}
    paths = set()
    section = None
    path = None
    have_header = False

    def close():
        if section is None or section["deleted"]:
            return
        name = section["new"] or section["rename"] or header_path(section["line"])
        if name is None:
            raise DiffError("FAIL: cannot name the file of: " + section["line"])
        paths.add(name)

    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if BINARY.match(line):
            raise DiffError("FAIL: binary diff, so no changed lines can be read: " + line)
        if line.startswith("diff --git "):
            close()
            section = {"line": line, "new": None, "rename": None, "deleted": False}
            path = None
            have_header = False
        elif section is not None and line.startswith("deleted file mode "):
            section["deleted"] = True
        elif section is not None and line.startswith("rename to "):
            section["rename"] = line[len("rename to "):]
        elif line.startswith("+++ "):
            target = line[4:].rstrip("\t")
            if target == "/dev/null":
                path = None
                if section is not None:
                    section["deleted"] = True
            elif target.startswith("b/") and len(target) > 2:
                path = target[2:]
                if section is not None:
                    section["new"] = path
            else:
                raise DiffError("FAIL: unrecognised file header: " + line)
            have_header = True
        elif line.startswith("@@"):
            match = HUNK.match(line)
            if not match:
                raise DiffError("FAIL: unrecognised hunk header: " + line)
            if not have_header:
                raise DiffError("FAIL: hunk with no '+++' file header: " + line)
            old = int(match.group(2) if match.group(2) is not None else 1)
            new = int(match.group(4) if match.group(4) is not None else 1)
            start = int(match.group(3))
            no_new_side = new == 0
            body = []
            while old > 0 or new > 0:
                if i >= len(lines):
                    raise DiffError("FAIL: hunk shorter than its header: " + line)
                text = lines[i]
                i += 1
                kind = text[:1] if text else " "
                if kind == " ":
                    old, new = old - 1, new - 1
                elif kind == "-":
                    old -= 1
                elif kind == "+":
                    new -= 1
                elif kind == "\\":
                    continue
                else:
                    raise DiffError("FAIL: unexpected line in hunk: " + text)
                if old < 0 or new < 0:
                    raise DiffError("FAIL: hunk longer than its header: " + line)
                body.append(kind)
            if path is not None and path.endswith(".rs"):
                result.setdefault(path, set()).update(hunk_lines(body, start, no_new_side))
        elif line[:1] in (" ", "+", "-") and not line.startswith("--- "):
            raise DiffError("FAIL: hunk longer than its header: " + line)
    close()
    return result, paths


def hunk_lines(body, start, no_new_side):
    # With no new-side lines the header's start names the line before the deletion point.
    marked = set()
    nxt = start + 1 if no_new_side else start
    has_context = " " in body
    k = 0
    while k < len(body):
        if body[k] == "+":
            marked.add(nxt)
            nxt += 1
            k += 1
        elif body[k] == " ":
            nxt += 1
            k += 1
        else:
            while k < len(body) and body[k] == "-":
                k += 1
            if nxt - 1 >= 1:
                marked.add(nxt - 1)
            if k < len(body) and body[k] == "+":
                continue
            # A pure deletion ending a hunk that has context sits at end of file: no following line.
            if k < len(body) or not has_context:
                marked.add(nxt)
    return marked


def overlapping(pkg, changed, whole):
    hits = []
    for mutant in whole:
        if mutant["package"] != pkg or mutant["file"] not in changed:
            continue
        span = mutant["span"]
        start, end = span["start"]["line"], span["end"]["line"]
        if any(start <= line <= end for line in changed[mutant["file"]]):
            hits.append(mutant)
    return hits


def classify(pkg, changed, whole, indiff):
    hits = overlapping(pkg, changed, whole)
    if indiff:
        listed = {mutant["name"] for mutant in indiff}
        dropped = [mutant["name"] for mutant in hits if mutant["name"] not in listed]
        if dropped:
            return (f"FAIL: {pkg}: in-diff listing dropped {len(dropped)} mutants "
                    f"on changed lines: {'; '.join(dropped[:3])}", 1)
        return f"RUN {pkg}: {len(indiff)} in-diff mutants", 0
    if hits:
        files = ", ".join(sorted({mutant["file"] for mutant in hits}))
        return (f"FAIL: {pkg}: {len(hits)} listed mutants on changed lines in {files} "
                "but the in-diff listing found none", 1)
    return f"SKIP: {pkg}: no mutant on a changed line", 0


def read_list(pkg, path):
    text = Path(path).read_text()
    if not text.strip():
        return []
    try:
        data = json.loads(text)
        if not isinstance(data, list):
            raise ValueError
        for mutant in data:
            mutant["name"], mutant["package"], mutant["file"]
            mutant["span"]["start"]["line"], mutant["span"]["end"]["line"]
    except (ValueError, KeyError, TypeError):
        raise DiffError(f"FAIL: {pkg}: unreadable mutant list {path}") from None
    return data


def git_env():
    env = {k: v for k, v in os.environ.items() if k not in GIT_ENV}
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    env["LC_ALL"] = "C"
    return env


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                          env=git_env(), check=False)


def resolve(root, rev):
    done = git(root, "rev-parse", "--verify", "--end-of-options", rev + "^{commit}")
    if done.returncode != 0:
        raise ScopeError(f"FAIL: revision does not resolve to a commit: {rev}")
    return done.stdout.decode().strip()


def show(root, sha, path):
    done = git(root, "show", "--end-of-options", f"{sha}:{path}")
    if done.returncode == 0:
        return done.stdout.decode()
    if ABSENT.search(done.stderr.decode()):
        return None
    raise ScopeError(f"FAIL: cannot read {path} at {sha}: {done.stderr.decode().strip()}")


def parse_toml(text):
    try:
        return tomllib.loads(text or "")
    except tomllib.TOMLDecodeError:
        return None


def cargo_env():
    return {k: v for k, v in git_env().items() if k not in ("LLVM_COV", "LLVM_PROFDATA")}


def packages(root):
    done = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1",
         "--manifest-path", str(Path(root) / "Cargo.toml")],
        capture_output=True, env=cargo_env(), check=False)
    if done.returncode != 0:
        raise ScopeError("FAIL: cargo metadata failed: " + done.stderr.decode().strip())
    return {package["name"]: package for package in json.loads(done.stdout)["packages"]}


def workspace_crates(root):
    crates = {}
    for name, package in packages(root).items():
        manifest = Path(package["manifest_path"]).resolve()
        crates[name] = manifest.parent.relative_to(Path(root).resolve()).as_posix()
    return crates


def check_paths(root, base, diff_text, head="HEAD"):
    named = diff_paths(diff_text)
    done = git(root, "-c", "core.quotePath=true", "diff", "--name-only", "-z", "--no-renames",
               "--diff-filter=d", "--no-ext-diff", base, head)
    if done.returncode != 0:
        raise ScopeError(f"FAIL: git diff --name-only {base} {head} failed: {done.stderr.decode().strip()}")
    listed = {p for p in done.stdout.decode().split("\0") if p.endswith(".rs")}
    if named != listed:
        raise DiffError(f"FAIL: the diff names {sorted(named - listed)} that git diff --name-only "
                        f"does not, and misses {sorted(listed - named)}")
    return sorted(named)


def tiers(text):
    data = parse_toml(text)
    if data is None:
        return None
    try:
        crates = data["t1"]["mutants_crates"]
        if not isinstance(crates, list):
            return None
        return set(crates)
    except (KeyError, TypeError):
        return None


def affected():
    selector = Path(__file__).resolve().parents[1] / "affected.py"
    spec = importlib.util.spec_from_file_location("affected", selector)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def changed_names(root, base_sha, head_sha):
    done = git(root, "diff", "--name-only", "-z", "--no-renames", "--no-ext-diff", base_sha, head_sha)
    if done.returncode != 0:
        raise ScopeError(f"FAIL: git diff --name-only {base_sha} {head_sha} failed: "
                         f"{done.stderr.decode().strip()}")
    try:
        return [p for p in done.stdout.decode().split("\0") if p]
    except UnicodeError:
        raise ScopeError("FAIL: a changed path is not UTF-8") from None


def owner_of(path, dirs):
    owner, size = None, -1
    for crate, directory in dirs.items():
        if directory == ".":
            n = 0
        elif path.startswith(directory + "/"):
            n = len(directory)
        else:
            continue
        if n > size:
            owner, size = crate, n
    return owner


def without_dependencies(manifest):
    data = {k: v for k, v in manifest.items() if k not in DEPENDENCY_TABLES}
    if isinstance(data.get("target"), dict):
        targets = {cfg: {k: v for k, v in table.items() if k not in DEPENDENCY_TABLES}
                   if isinstance(table, dict) else table for cfg, table in data["target"].items()}
        data["target"] = {cfg: table for cfg, table in targets.items() if table != {}}
        if not data["target"]:
            del data["target"]
    if isinstance(data.get("workspace"), dict):
        data["workspace"] = {k: v for k, v in data["workspace"].items() if k != "dependencies"}
    return data


def dependency_only(root, base_sha, head_sha, path):
    if Path(path).name != "Cargo.toml":
        return False
    old, new = show(root, base_sha, path), show(root, head_sha, path)
    if old is None or new is None:
        return False
    old_data, new_data = parse_toml(old), parse_toml(new)
    return (old_data is not None and new_data is not None
            and without_dependencies(old_data) == without_dependencies(new_data))


def within(path, directory):
    return directory in (".", "") or path == directory or path.startswith(directory + "/")


def join(directory, name):
    return name if directory in (".", "") else f"{directory}/{name}"


def build_scripts(root, sha, directory, present):
    manifest = parse_toml(show(root, sha, join(directory, "Cargo.toml")))
    package = manifest.get("package") if isinstance(manifest, dict) else None
    build = package.get("build") if isinstance(package, dict) else None
    if isinstance(build, str):
        return [build]
    if isinstance(build, list):
        return [b for b in build if isinstance(b, str)]
    if build is False:
        return []
    return ["build.rs"] if present(join(directory, "build.rs")) else []


def script_path(directory, script):
    if posixpath.isabs(script):
        return None
    path = posixpath.normpath(join(directory, script))
    return None if path == ".." or path.startswith("../") else path


def script_crates(root, shas, mutants, dirs):
    found = set()
    for crate in sorted(mutants & set(dirs)):
        for sha in shas:
            present = lambda path, sha=sha: show(root, sha, path) is not None
            if build_scripts(root, sha, dirs[crate], present):
                found.add(crate)
    return found


def exempt(root, base_sha, head_sha, path, docs_only):
    return docs_only(path) or path == "Cargo.lock" or dependency_only(root, base_sha, head_sha, path)


def contract(root, sha, dirs):
    head_tiers = tiers(show(root, sha, "coverage-tiers.toml"))
    return head_tiers if head_tiers is not None else set(dirs)


def scope_crates(root, base, head, workspace=None):
    base_sha, head_sha = resolve(root, base), resolve(root, head)
    dirs = workspace_crates(workspace or root)
    mutants = contract(root, head_sha, dirs)
    docs_only = affected().docs_only
    built = script_crates(root, (base_sha, head_sha), mutants, dirs)
    selected = set()
    for path in changed_names(root, base_sha, head_sha):
        selected.update(built)
        if exempt(root, base_sha, head_sha, path, docs_only):
            continue
        if path in SCOPE_FILES:
            selected.update(mutants)
        elif posixpath.basename(path) == "Cargo.toml":
            owner = owner_of(path, dirs)
            selected.update(mutants if owner is None or dirs[owner] == "." else {owner})
    return sorted(selected & mutants)


def features_of(text, crate):
    data = parse_toml(text)
    try:
        found = data["t1"]["mutants_features"][crate]
    except (KeyError, TypeError):
        return []
    if not isinstance(found, list) or not all(isinstance(f, str) for f in found):
        raise ScopeError(f"FAIL: [t1].mutants_features.{crate} is not a list of strings")
    return found


def dep_tokens(text):
    tokens = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"(?<!\\):(?:\s|$)", line, maxsplit=1)
        tokens.append(parts[0])
        if len(parts) == 2:
            tokens.extend(re.split(r"(?<!\\)\s+", parts[1].strip()))
    return [t.replace("\\ ", " ") for t in tokens if t]


def production_inputs(tree, package, features, target):
    kinds = {k for t in package["targets"] for k in t["kind"]}
    selectors = (["--lib"] if kinds & PRODUCTION_LIB else []) + (["--bins"] if "bin" in kinds else [])
    if not selectors:
        raise ScopeError(f"FAIL: {package['name']}: no library or binary target to check")
    argv = ["cargo", "check", "--package", package["name"], *selectors, "--message-format=json",
            "--target-dir", str(target), "--manifest-path", str(tree / "Cargo.toml")]
    for feature in features:
        argv += ["--features", feature]
    done = subprocess.run(argv, cwd=tree, capture_output=True, env=cargo_env(), check=False)
    if done.returncode != 0:
        tail = done.stderr.decode(errors="replace").strip().splitlines()[-5:]
        raise ScopeError(f"FAIL: {package['name']}: cargo check of its production targets failed: "
                         + " | ".join(tail))
    found, read = set(), 0
    for line in done.stdout.decode(errors="replace").splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if (not isinstance(message, dict) or message.get("reason") != "compiler-artifact"
                or message.get("package_id") != package["id"]
                or not set(message.get("target", {}).get("kind", [])) & (PRODUCTION_LIB | {"bin"})):
            continue
        for artifact in message.get("filenames", []):
            artifact = Path(artifact)
            candidates = [artifact.with_suffix(".d")]
            if artifact.name.startswith("lib"):
                candidates.append(artifact.with_name(artifact.stem[3:] + ".d"))
            info = next((c for c in candidates if c.is_file()), None)
            if info is None:
                continue
            read += 1
            for token in dep_tokens(info.read_text(errors="replace")):
                path = Path(token) if os.path.isabs(token) else tree / token
                try:
                    stat = os.stat(path)
                except OSError:
                    raise ScopeError(f"FAIL: {package['name']}: dep-info entry {json.dumps(token)} in "
                                     f"{info.name} does not resolve to a file") from None
                found.add((stat.st_dev, stat.st_ino))
    if read == 0:
        raise ScopeError(f"FAIL: {package['name']}: cargo check wrote no dep-info for its production targets")
    return found


def compiled(root, base, head, workspace, target):
    base_sha, head_sha = resolve(root, base), resolve(root, head)
    tree = Path(os.path.realpath(workspace))
    found = packages(tree)
    dirs = {name: Path(os.path.realpath(Path(p["manifest_path"]).parent)).relative_to(tree).as_posix()
            for name, p in found.items()}
    tiers_text = show(root, head_sha, "coverage-tiers.toml")
    mutants = contract(root, head_sha, dirs)
    identities = {}
    for path in changed_names(root, base_sha, head_sha):
        try:
            stat = os.stat(tree / path)
        except OSError:
            continue
        identities[(stat.st_dev, stat.st_ino)] = path
    if not identities:
        return {}
    whole = set(scope_crates(root, base, head, workspace))
    result = {}
    for crate in sorted((mutants & set(found)) - whole):
        inputs = production_inputs(tree, found[crate], features_of(tiers_text, crate), Path(target))
        hits = sorted(path for key, path in identities.items() if key in inputs)
        if hits:
            result[crate] = hits
    return result


def read_files(crate, path):
    text = Path(path).read_text()
    if not text.strip():
        raise DiffError(f"FAIL: {crate}: cargo mutants --list-files printed nothing")
    try:
        data = json.loads(text)
        if not isinstance(data, list):
            raise ValueError
        listed = set()
        for entry in data:
            if not isinstance(entry, dict) or entry["package"] != crate or not isinstance(entry["path"], str):
                raise ValueError
            listed.add(entry["path"])
    except (ValueError, KeyError, TypeError):
        raise DiffError(f"FAIL: {crate}: cargo mutants --list-files printed no file list") from None
    return listed


class LexError(Exception):
    pass


STRING = re.compile(r'(b|c)?r(#*)"|(b|c)?"')
ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", "0": "\0", "'": "'", '"': '"'}
WORD = re.compile(r"\w+")


def unescape(body):
    out, i = [], 0
    while i < len(body):
        ch = body[i]
        i += 1
        if ch != "\\":
            out.append(ch)
            continue
        if i >= len(body):
            raise LexError("dangling escape")
        kind = body[i]
        i += 1
        if kind in ESCAPES:
            out.append(ESCAPES[kind])
        elif kind == "x":
            out.append(chr(int(body[i:i + 2], 16)))
            i += 2
        elif kind == "u" and body[i:i + 1] == "{":
            end = body.index("}", i)
            out.append(chr(int(body[i + 1:end].replace("_", ""), 16)))
            i = end + 1
        elif kind == "\n":
            while i < len(body) and body[i] in " \t\n\r":
                i += 1
        else:
            raise LexError(f"unknown escape \\{kind}")
    return "".join(out)


def tokens(text):
    found, i, n = [], 0, len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif text.startswith("/*", i):
            depth, i = 1, i + 2
            while depth:
                if i >= n:
                    raise LexError("unterminated block comment")
                if text.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif text.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
        elif (literal := STRING.match(text, i)) is not None:
            start = literal.end()
            if literal.group(2) is not None:
                close = '"' + literal.group(2)
                end = text.find(close, start)
                if end < 0:
                    raise LexError("unterminated raw string")
                value, i = text[start:end], end + len(close)
            else:
                end = start
                while end < n and text[end] != '"':
                    end += 2 if text[end] == "\\" else 1
                if end >= n:
                    raise LexError("unterminated string")
                value, i = unescape(text[start:end]), end + 1
            plain = literal.group(1) is None and literal.group(3) is None
            found.append(("str" if plain else "bytes", value))
        elif ch == "'" or text.startswith("b'", i):
            j = i + (2 if ch == "b" else 1)
            if text.startswith("\\", j):
                end = text.find("'", j + 2)
                if end < 0:
                    raise LexError("unterminated character literal")
                found.append(("char", text[j:end]))
                i = end + 1
            elif j + 1 < n and text[j + 1] == "'":
                found.append(("char", text[j]))
                i = j + 2
            else:
                word = WORD.match(text, j)
                found.append(("lifetime", word.group() if word else ""))
                i = word.end() if word else j
        elif ch.isalpha() or ch == "_":
            word = WORD.match(text, i)
            i = word.end()
            if word.group() == "r" and text.startswith("#", i) and (raw := WORD.match(text, i + 1)):
                word, i = raw, raw.end()
            found.append(("ident", word.group()))
        elif ch.isdigit():
            i = WORD.match(text, i).end()
            found.append(("number", ""))
        else:
            found.append(("punct", ch))
            i += 1
    return found


PAIRS = {"(": ")", "[": "]", "{": "}"}
CFG_OPEN = [("punct", "#"), ("punct", "["), ("ident", "cfg"), ("punct", "(")]


def closing(toks, at):
    depth = 0
    for k in range(at, len(toks)):
        kind, value = toks[k]
        if kind == "punct" and value in PAIRS:
            depth += 1
        elif kind == "punct" and value in PAIRS.values():
            depth -= 1
            if depth == 0:
                return k
    raise LexError("unbalanced delimiters")


def test_only(pred):
    if pred == [("ident", "test")]:
        return True
    if pred[:2] != [("ident", "all"), ("punct", "(")] or closing(pred, 1) != len(pred) - 1:
        return False
    args, depth, current = [], 0, []
    for tok in pred[2:-1]:
        if tok[0] == "punct" and tok[1] in PAIRS:
            depth += 1
        elif tok[0] == "punct" and tok[1] in PAIRS.values():
            depth -= 1
        if depth == 0 and tok == ("punct", ","):
            args.append(current)
            current = []
        else:
            current.append(tok)
    args.append(current)
    return [("ident", "test")] in args


def test_module_end(toks, at):
    if toks[at:at + 4] != CFG_OPEN:
        return None
    close = closing(toks, at + 3)
    if not test_only(toks[at + 4:close]) or toks[close + 1:close + 2] != [("punct", "]")]:
        return None
    k = close + 2
    while toks[k:k + 2] == [("punct", "#"), ("punct", "[")]:
        k = closing(toks, k + 1) + 1
    if toks[k:k + 1] == [("ident", "pub")]:
        k += 1
        if toks[k:k + 1] == [("punct", "(")]:
            k = closing(toks, k) + 1
    if (toks[k:k + 1] == [("ident", "mod")] and k + 2 < len(toks) and toks[k + 1][0] == "ident"
            and toks[k + 2] == ("punct", "{")):
        return closing(toks, k + 2)
    return None


INCLUDE_MACROS = ("include_str", "include_bytes")
COLONS = [("punct", ":"), ("punct", ":")]


def plain_path(toks, k):
    if k < 2 or toks[k - 2:k] != COLONS:
        return True
    if k < 3 or toks[k - 3] not in (("ident", "std"), ("ident", "core")):
        return False
    j = k - 3
    return j < 2 or toks[j - 2:j] != COLONS or j < 3 or toks[j - 3][0] != "ident"


def direct_call(toks, k):
    if not plain_path(toks, k) or toks[k + 1:k + 2] != [("punct", "!")] or k + 2 >= len(toks) \
            or toks[k + 2][0] != "punct" or toks[k + 2][1] not in PAIRS:
        return None
    end = closing(toks, k + 2)
    args = toks[k + 3:end]
    if args and args[0][0] == "str" and args[1:] in ([], [("punct", ",")]):
        return end, args[0][1]
    return None


def includes(text):
    toks = tokens(text)
    literal, indirect, k = [], False, 0
    while k < len(toks):
        end = test_module_end(toks, k)
        if end is not None:
            k = end + 1
        elif (toks[k] == ("ident", "macro_rules") and toks[k + 1:k + 2] == [("punct", "!")]
              and k + 3 < len(toks) and toks[k + 2][0] == "ident" and toks[k + 3][0] == "punct"
              and toks[k + 3][1] in PAIRS):
            end = closing(toks, k + 3)
            indirect = indirect or any(tok[0] == "ident" and tok[1] in INCLUDE_MACROS
                                       for tok in toks[k + 4:end])
            k = end + 1
        elif toks[k][0] == "ident" and toks[k][1] in INCLUDE_MACROS:
            call = direct_call(toks, k)
            if call is None:
                indirect = True
                k += 1
            else:
                literal.append(call[1])
                k = call[0] + 1
        else:
            k += 1
    return literal, indirect


TEST_ONLY_DIRS = ("tests", "benches", "examples")


def test_only_file(path, dirs):
    owner = owner_of(path, dirs)
    if owner is None:
        return False
    directory = dirs[owner]
    rest = path if directory in (".", "") else path[len(directory) + 1:]
    return rest.split("/", 1)[0] in TEST_ONLY_DIRS


def embeds(root, base, head, workspace):
    base_sha, head_sha = resolve(root, base), resolve(root, head)
    tree = Path(os.path.realpath(workspace))
    dirs = workspace_crates(tree)
    listing = git(root, "ls-tree", "-r", "-z", "--full-tree", "--name-only", head_sha)
    if listing.returncode != 0:
        raise ScopeError(f"FAIL: git ls-tree {head_sha} failed: {listing.stderr.decode().strip()}")
    indirect, targets = None, {}
    for name in sorted(n.decode() for n in listing.stdout.split(b"\0") if n.endswith(b".rs")):
        if test_only_file(name, dirs) or (tree / name).is_symlink():
            continue
        file = tree / name
        try:
            literal, dynamic = includes(file.read_text())
        except (OSError, UnicodeError, ValueError, LexError) as exc:
            raise ScopeError(f"FAIL: cannot scan {name} for include_str!/include_bytes!: {exc}") from None
        if dynamic and indirect is None:
            indirect = name
        site = owner_of(name, dirs)
        for value in literal:
            target = Path(os.path.realpath(Path(value) if os.path.isabs(value) else file.parent / value))
            if not target.is_file() or not contains(tree, target):
                continue
            key = Path(os.path.relpath(target, tree)).as_posix()
            targets.setdefault(key, set()).add(site)
    if indirect is not None and not changed_names(root, base_sha, head_sha):
        indirect = None
    return {"indirect": indirect,
            "targets": {k: sorted(s, key=lambda v: (v is None, v or "")) for k, s in sorted(targets.items())}}


def read_embeds(crate, path):
    try:
        data = json.loads(Path(path).read_text())
        if (not isinstance(data, dict) or not isinstance(data.get("targets"), dict)
                or not (data.get("indirect") is None or isinstance(data["indirect"], str))):
            raise ValueError
    except ValueError:
        raise DiffError(f"FAIL: {crate}: unreadable include-site list {path}") from None
    return data


def unlisted(crate, files, inputs, workspace, embed_file):
    listed = read_files(crate, files)
    try:
        data = json.loads(Path(inputs).read_text())
        changed = data.get(crate, [])
        if not isinstance(changed, list) or not all(isinstance(p, str) for p in changed):
            raise ValueError
    except (ValueError, AttributeError):
        raise DiffError(f"FAIL: {crate}: unreadable compiled-input list {inputs}") from None
    found = read_embeds(crate, embed_file)
    if not changed:
        return None
    if found["indirect"] is not None:
        return f"whole: {crate}: include_str/include_bytes used indirectly in {found['indirect']}"
    tree = Path(os.path.realpath(workspace))
    sites = {}
    for target, owners in found["targets"].items():
        try:
            stat = os.stat(tree / target)
        except OSError:
            continue
        sites[(stat.st_dev, stat.st_ino)] = set(owners)
    for path in changed:
        try:
            stat = os.stat(tree / path)
        except OSError:
            raise DiffError(f"FAIL: {crate}: changed {path} is not in the snapshot") from None
        owners = sites.get((stat.st_dev, stat.st_ino), set())
        if crate in owners or None in owners:
            return f"whole: {crate}: changed {path} is embedded by include_str!/include_bytes!"
    for name in sorted(listed):
        if not name.endswith(".rs"):
            return f"whole: {crate}: walked source {name} is not a .rs file the in-diff mapping reads"
    for path in changed:
        if path not in listed:
            return f"whole: {crate}: changed {path} is compiled into {crate} but not walked by cargo-mutants"
    return None


def contains(directory, path):
    try:
        anchor = os.stat(directory)
    except OSError:
        return False
    for candidate in (path, *path.parents):
        try:
            if os.path.samestat(os.stat(candidate), anchor):
                return True
        except OSError:
            continue
    return False


def unmappable(root, head, workspace):
    sha = resolve(root, head)
    dirs = workspace_crates(workspace)
    mutants = sorted(contract(root, sha, dirs) & set(dirs))
    listing = git(root, "ls-tree", "-r", "-z", "--full-tree", sha)
    if listing.returncode != 0:
        raise ScopeError(f"FAIL: git ls-tree {sha} failed: {listing.stderr.decode().strip()}")
    paths, links = set(), []
    for record in listing.stdout.split(b"\0"):
        if not record:
            continue
        meta, _, raw = record.partition(b"\t")
        name = raw.decode()
        if any(unicodedata.category(ch) == "Cc" for ch in name):
            shown = json.dumps(name, ensure_ascii=False).translate({c: f"\\u{c:04x}" for c in range(0x7f, 0xa0)})
            return (f"FAIL: --in-diff: tracked path {shown} contains a "
                    "newline or control character; in-diff mapping cannot name it — use the "
                    "whole-package run")
        paths.add(name)
        if meta.split(b" ")[0] == b"120000":
            links.append(raw.decode())
    tree = Path(os.path.realpath(workspace))
    resolved = {}
    for link in sorted(links):
        place = tree / link
        target = Path(os.path.realpath(place))
        if os.path.isabs(os.readlink(place)) or not contains(tree, target):
            return (f"FAIL: --in-diff: symlink {link} points outside the repository; in-diff "
                    "mapping cannot follow aliases — use the whole-package run")
        resolved[link] = (Path(os.path.realpath(place.parent)), target)
    for crate in mutants:
        directory = dirs[crate]
        home = Path(os.path.realpath(tree / directory))
        for link, (parent, target) in resolved.items():
            if (within(link, directory) or contains(home, parent) or contains(home, target)
                    or contains(target, home)):
                return (f"FAIL: --in-diff: symlink {link} in mutation crate {crate}; in-diff mapping "
                        "cannot follow aliases — use the whole-package run")
        for script in build_scripts(root, sha, directory, paths.__contains__):
            if script_path(directory, script) is None:
                return (f"FAIL: --in-diff: build script {script} of mutation crate {crate} "
                        "lies outside the repository — use the whole-package run")
    return None


def untrusted_history(root):
    return affected().untrusted_history(Path(root))


def snapshot(root, rev, dest):
    sha = resolve(root, rev)
    listing = git(root, "ls-tree", "-r", "-z", "--full-tree", sha)
    if listing.returncode != 0:
        raise ScopeError(f"FAIL: git ls-tree {sha} failed: {listing.stderr.decode().strip()}")
    entries = []
    for record in listing.stdout.split(b"\0"):
        if not record:
            continue
        meta, _, raw = record.partition(b"\t")
        mode, kind, oid = meta.decode().split(" ")
        path = raw.decode()
        parts = path.split("/")
        if any(p in ("", ".", "..") or p.lower() == ".git" for p in parts):
            raise ScopeError(f"FAIL: HEAD names an unsafe path: {path!r}")
        if kind != "blob" or mode not in ("100644", "100755", "120000"):
            raise ScopeError(f"FAIL: HEAD has a {kind} at {path} (mode {mode}) that a snapshot cannot hold")
        entries.append((mode, oid, path))
    done = subprocess.run(["git", "-C", str(root), "cat-file", "--batch"], capture_output=True,
                          env=git_env(), check=False,
                          input="".join(oid + "\n" for _, oid, _ in entries).encode())
    if done.returncode != 0:
        raise ScopeError(f"FAIL: git cat-file --batch failed: {done.stderr.decode().strip()}")
    out, at, blobs = done.stdout, 0, []
    for _, oid, path in entries:
        end = out.index(b"\n", at)
        header = out[at:end].decode().split(" ")
        if len(header) != 3 or header[0] != oid or header[1] != "blob":
            raise ScopeError(f"FAIL: cannot read {path} ({oid}) from the object store")
        size = int(header[2])
        blobs.append(out[end + 1:end + 1 + size])
        at = end + 1 + size + 1
    target = Path(dest)
    target.mkdir(mode=0o700)

    def place(path):
        for parent in Path(path).parents:
            if (target / parent).is_symlink():
                raise ScopeError(f"FAIL: HEAD places {path} beneath the symlink {parent}")
        file = target / path
        file.parent.mkdir(parents=True, exist_ok=True)
        return file

    links = []
    for (mode, _, path), blob in zip(entries, blobs):
        if mode == "120000":
            links.append((path, blob))
            continue
        file = place(path)
        fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(blob)
        os.chmod(file, 0o755 if mode == "100755" else 0o644)
    for path, blob in links:
        os.symlink(os.fsdecode(blob), place(path))


def main(argv):
    command = argv[0] if argv else ""
    try:
        if len(argv) == 2 and command == "changed-lines":
            data = changed_lines(read_diff(argv[1]))
            print(json.dumps({k: sorted(v) for k, v in sorted(data.items())}))
        elif len(argv) == 5 and command == "classify":
            pkg = argv[1]
            changed = changed_lines(read_diff(argv[2]))
            line, status = classify(pkg, changed, read_list(pkg, argv[3]), read_list(pkg, argv[4]))
            print(line)
            return status
        elif len(argv) in (4, 5) and command == "scope":
            print(json.dumps(scope_crates(*argv[1:])))
        elif len(argv) in (4, 5) and command == "paths":
            for name in check_paths(argv[1], argv[2], read_diff(argv[3]), *argv[4:]):
                print(name)
        elif len(argv) == 2 and command == "history":
            problem = untrusted_history(argv[1])
            if problem:
                print(problem)
                return 1
        elif len(argv) == 4 and command == "snapshot":
            snapshot(argv[1], argv[2], argv[3])
        elif len(argv) == 6 and command == "compiled":
            print(json.dumps(compiled(*argv[1:])))
        elif len(argv) == 5 and command == "embeds":
            print(json.dumps(embeds(*argv[1:])))
        elif len(argv) == 6 and command == "unlisted":
            line = unlisted(*argv[1:])
            if line:
                print(line)
        elif len(argv) == 4 and command == "unmappable":
            problem = unmappable(*argv[1:])
            if problem:
                print(problem)
                return 1
        else:
            print("FAIL: usage: mutation-diff.py changed-lines <diff> | classify <pkg> <diff> "
                  "<whole> <indiff> | scope <root> <base> <head> [<workspace>] | paths <root> <base> "
                  "<diff> [<head>] | history <root> | snapshot <root> <rev> <dest> | "
                  "compiled <root> <base> <head> <workspace> <target> | embeds <root> <base> <head> <workspace> | "
                  "unlisted <crate> <files> <compiled> <workspace> <embeds> | unmappable <root> <head> <workspace>",
                  file=sys.stderr)
            return 1
    except (DiffError, ScopeError) as exc:
        print(exc, file=sys.stdout if command == "classify" else sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
