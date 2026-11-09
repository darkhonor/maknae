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
PRODUCTION_LIB = frozenset(("lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"))


class DiffError(Exception):
    pass


class InputError(Exception):
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
        raise InputError(f"FAIL: revision does not resolve to a commit: {rev}")
    return done.stdout.decode().strip()


def show(root, sha, path):
    done = git(root, "show", "--end-of-options", f"{sha}:{path}")
    if done.returncode == 0:
        return done.stdout.decode()
    if ABSENT.search(done.stderr.decode()):
        return None
    raise InputError(f"FAIL: cannot read {path} at {sha}: {done.stderr.decode().strip()}")


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
        raise InputError("FAIL: cargo metadata failed: " + done.stderr.decode().strip())
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
        raise InputError(f"FAIL: git diff --name-only {base} {head} failed: {done.stderr.decode().strip()}")
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
        raise InputError(f"FAIL: git diff --name-only {base_sha} {head_sha} failed: "
                         f"{done.stderr.decode().strip()}")
    try:
        return [p for p in done.stdout.decode().split("\0") if p]
    except UnicodeError:
        raise InputError("FAIL: a changed path is not UTF-8") from None


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


def contract(root, sha, dirs):
    head_tiers = tiers(show(root, sha, "coverage-tiers.toml"))
    return head_tiers if head_tiers is not None else set(dirs)


def features_of(text, crate):
    data = parse_toml(text)
    try:
        found = data["t1"]["mutants_features"][crate]
    except (KeyError, TypeError):
        return []
    if not isinstance(found, list) or not all(isinstance(f, str) for f in found):
        raise InputError(f"FAIL: [t1].mutants_features.{crate} is not a list of strings")
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


def selectors(package):
    kinds = {k for t in package["targets"] for k in t["kind"]}
    found = (["--lib"] if kinds & PRODUCTION_LIB else []) + (["--bins"] if "bin" in kinds else [])
    if not found:
        raise InputError(f"FAIL: {package['name']}: no library or binary target to check")
    return found


def check_inputs(tree, label, args, features, target, members):
    argv = ["cargo", "check", *args, "--tests", "--config", 'profile.mutation-discovery.inherits="test"',
            "--profile", "mutation-discovery", "--message-format=json",
            "--target-dir", str(target), "--manifest-path", str(tree / "Cargo.toml")]
    for feature in features:
        argv += ["--features", feature]
    done = subprocess.run(argv, cwd=tree, capture_output=True, env=cargo_env(), check=False)
    if done.returncode != 0:
        tail = done.stderr.decode(errors="replace").strip().splitlines()[-5:]
        raise InputError(f"FAIL: {label}: cargo check of its production targets failed: " + " | ".join(tail))
    found, read = {}, 0
    for line in done.stdout.decode(errors="replace").splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if (not isinstance(message, dict) or message.get("reason") != "compiler-artifact"
                or message.get("package_id") not in members
                or not set(message.get("target", {}).get("kind", [])) & (PRODUCTION_LIB | {"bin"})
                or (message.get("profile") or {}).get("test") is not False):
            continue
        name = members[message["package_id"]]
        infos = set()
        for artifact in message.get("filenames", []):
            artifact = Path(artifact)
            candidates = [artifact.with_suffix(".d")]
            if artifact.name.startswith("lib"):
                candidates.append(artifact.with_name(artifact.stem[3:] + ".d"))
            infos.update(c for c in candidates if c.is_file())
        if len(infos) != 1:
            raise InputError(f"FAIL: {name}: cannot locate exactly one dep-info file for its "
                             f"{message['target'].get('name')} target (found {len(infos)})")
        for info in infos:
            read += 1
            for token in dep_tokens(info.read_text(errors="replace")):
                path = Path(token) if os.path.isabs(token) else tree / token
                try:
                    stat = os.stat(path)
                except OSError:
                    raise InputError(f"FAIL: {name}: dep-info entry {json.dumps(token)} in "
                                     f"{info.name} does not resolve to a file") from None
                found.setdefault(name, {})[(stat.st_dev, stat.st_ino)] = path
    if read == 0:
        raise InputError(f"FAIL: {label}: cargo check wrote no dep-info for its production targets")
    return found


def production_inputs(tree, package, features, target):
    found = check_inputs(tree, package["name"], ["--package", package["name"], *selectors(package)],
                         features, target, {package["id"]: package["name"]})
    return set(found.get(package["name"], {}))


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
        if not path.endswith(".rs"):
            continue
        try:
            stat = os.stat(tree / path)
        except OSError:
            continue
        identities[(stat.st_dev, stat.st_ino)] = path
    if not identities:
        return {}
    result = {}
    for crate in sorted(mutants & set(found)):
        inputs = production_inputs(tree, found[crate], features_of(tiers_text, crate), Path(target))
        hits = sorted(path for key, path in identities.items() if key in inputs and within(path, dirs[crate]))
        if hits:
            result[crate] = hits
    return result


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


ROOT_CONFIG = {name.casefold(): name for name in ("coverage-tiers.toml", "rust-toolchain", "rust-toolchain.toml")}
CARGO_CONFIG = {name.casefold(): name for name in ("mutants.toml", "config", "config.toml")}


def config_path(path):
    parts = path.split("/")
    if parts[0].casefold() == ".cargo":
        rest = parts[1:]
        if len(rest) == 1:
            rest = [CARGO_CONFIG.get(rest[0].casefold(), rest[0])]
        return "/".join([".cargo", *rest])
    if len(parts) == 1 and parts[0].casefold() in ROOT_CONFIG:
        return ROOT_CONFIG[parts[0].casefold()]
    if parts[-1].casefold() == "cargo.toml":
        return "/".join([*parts[:-1], "Cargo.toml"])
    return None


def prefixes(path):
    parts = path.split("/")
    return ["/".join(parts[:k]) for k in range(1, len(parts))]


def config_guard(root, head):
    sha = resolve(root, head)
    listing = git(root, "ls-tree", "-r", "-z", "--full-tree", sha)
    if listing.returncode != 0:
        raise InputError(f"FAIL: git ls-tree {sha} failed: {listing.stderr.decode().strip()}")
    entries = []
    for record in listing.stdout.split(b"\0"):
        if record:
            meta, _, raw = record.partition(b"\t")
            entries.append((meta.split(b" ")[0], raw.decode()))
    configs = {}
    for _, path in entries:
        canonical = config_path(path)
        if canonical is not None and canonical != path:
            return f"FAIL: --in-diff: {path} is a case variant of the config path {canonical}; rename it"
        if canonical is not None:
            for directory in prefixes(path):
                configs.setdefault(directory.casefold(), (directory, path))
    for _, path in entries:
        for directory in prefixes(path) + [path]:
            found = configs.get(directory.casefold())
            if found is not None and found[0] != directory:
                return (f"FAIL: --in-diff: {path} is a case variant of the config path {found[1]}; "
                        "rename it")
    for mode, path in entries:
        if mode == b"120000" and config_path(path) is not None:
            return f"FAIL: --in-diff: {path} is a symlink; config inputs must be regular files"
    return None


MUTANTS_CONFIG_KEYS = frozenset(("exclude_globs", "exclude_re"))


def unmodelled_config(root, sha):
    text = show(root, sha, ".cargo/mutants.toml")
    if text is None:
        return None
    data = parse_toml(text)
    if data is None:
        return "FAIL: --in-diff: .cargo/mutants.toml does not parse — use the whole-package run"
    for key in sorted(set(data) - MUTANTS_CONFIG_KEYS):
        return (f"FAIL: --in-diff: .cargo/mutants.toml sets {key}, which changes what cargo-mutants builds "
                "and the in-diff checks do not model — use the whole-package run")
    return None


def unmappable(root, head, workspace):
    sha = resolve(root, head)
    problem = unmodelled_config(root, sha)
    if problem:
        return problem
    dirs = workspace_crates(workspace)
    mutants = sorted(contract(root, sha, dirs) & set(dirs))
    listing = git(root, "ls-tree", "-r", "-z", "--full-tree", sha)
    if listing.returncode != 0:
        raise InputError(f"FAIL: git ls-tree {sha} failed: {listing.stderr.decode().strip()}")
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
        problem = non_rs_source(root, sha, crate, directory, paths)
        if problem:
            return problem
    return None


def target_paths(manifest):
    if not isinstance(manifest, dict):
        return []
    lib = manifest.get("lib")
    found = [("[lib]", lib.get("path"))] if isinstance(lib, dict) else []
    for kind in ("bin", "test"):
        tables = manifest.get(kind)
        if isinstance(tables, list):
            found += [(f"[[{kind}]]", t.get("path")) for t in tables if isinstance(t, dict)]
    return [(kind, p) for kind, p in found if isinstance(p, str)]


def non_rs_source(root, sha, crate, directory, paths):
    targets = target_paths(parse_toml(show(root, sha, join(directory, "Cargo.toml"))))
    for kind, target in targets:
        resolved = script_path(directory, target) or target
        if kind != "[[test]]" and not within(resolved, directory):
            return (f"FAIL: --in-diff: {kind} path {target} of mutation crate {crate} resolves to {resolved}, "
                    f"outside {directory}; a mutation crate's targets must live inside its directory")
    for kind, target in targets:
        if not target.endswith(".rs"):
            shown = script_path(directory, target) or target
            return (f"FAIL: --in-diff: {shown} is compiled into mutation crate {crate} but does not end in .rs; "
                    "the in-diff mapping cannot read it — rename it to .rs")
    for path in sorted(p for p in paths if within(p, directory)):
        if path.casefold().endswith(".rs") and not path.endswith(".rs"):
            return (f"FAIL: --in-diff: {path} ends in a case variant of .rs; the in-diff mapping cannot read it "
                    "— rename it to .rs")
    return None


def folded(path):
    return unicodedata.normalize("NFC", path).casefold()


def tracked(pkg, whole, root, head):
    sha = resolve(root, head)
    listing = git(root, "ls-tree", "-r", "-z", "--full-tree", "--name-only", sha)
    if listing.returncode != 0:
        raise InputError(f"FAIL: git ls-tree {sha} failed: {listing.stderr.decode().strip()}")
    paths = set(listing.stdout.decode().split("\0"))
    spellings = {folded(p) for p in paths}
    for mutant in whole:
        if mutant["file"] not in paths:
            hint = " — rename the tracked file to that spelling" if folded(mutant["file"]) in spellings else ""
            return (f"FAIL: {pkg}: cargo-mutants walks {mutant['file']} under a spelling the tracked tree at HEAD "
                    f"does not have; the in-diff mapping cannot read it{hint}")
    return None


def untrusted_history(root):
    return affected().untrusted_history(Path(root))


def snapshot(root, rev, dest):
    sha = resolve(root, rev)
    listing = git(root, "ls-tree", "-r", "-z", "--full-tree", sha)
    if listing.returncode != 0:
        raise InputError(f"FAIL: git ls-tree {sha} failed: {listing.stderr.decode().strip()}")
    entries = []
    for record in listing.stdout.split(b"\0"):
        if not record:
            continue
        meta, _, raw = record.partition(b"\t")
        mode, kind, oid = meta.decode().split(" ")
        path = raw.decode()
        parts = path.split("/")
        if any(p in ("", ".", "..") or p.lower() == ".git" for p in parts):
            raise InputError(f"FAIL: HEAD names an unsafe path: {path!r}")
        if kind != "blob" or mode not in ("100644", "100755", "120000"):
            raise InputError(f"FAIL: HEAD has a {kind} at {path} (mode {mode}) that a snapshot cannot hold")
        entries.append((mode, oid, path))
    done = subprocess.run(["git", "-C", str(root), "cat-file", "--batch"], capture_output=True,
                          env=git_env(), check=False,
                          input="".join(oid + "\n" for _, oid, _ in entries).encode())
    if done.returncode != 0:
        raise InputError(f"FAIL: git cat-file --batch failed: {done.stderr.decode().strip()}")
    out, at, blobs = done.stdout, 0, []
    for _, oid, path in entries:
        end = out.index(b"\n", at)
        header = out[at:end].decode().split(" ")
        if len(header) != 3 or header[0] != oid or header[1] != "blob":
            raise InputError(f"FAIL: cannot read {path} ({oid}) from the object store")
        size = int(header[2])
        blobs.append(out[end + 1:end + 1 + size])
        at = end + 1 + size + 1
    target = Path(dest)
    target.mkdir(mode=0o700)

    def place(path):
        for parent in Path(path).parents:
            if (target / parent).is_symlink():
                raise InputError(f"FAIL: HEAD places {path} beneath the symlink {parent}")
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
        elif len(argv) == 3 and command == "config-guard":
            problem = config_guard(*argv[1:])
            if problem:
                print(problem)
                return 1
        elif len(argv) == 5 and command == "tracked":
            problem = tracked(argv[1], read_list(argv[1], argv[2]), argv[3], argv[4])
            if problem:
                print(problem)
                return 1
        elif len(argv) == 4 and command == "unmappable":
            problem = unmappable(*argv[1:])
            if problem:
                print(problem)
                return 1
        else:
            print("FAIL: usage: mutation-diff.py changed-lines <diff> | classify <pkg> <diff> "
                  "<whole> <indiff> | paths <root> <base> <diff> [<head>] | history <root> | "
                  "snapshot <root> <rev> <dest> | compiled <root> <base> <head> <workspace> <target> | "
                  "tracked <pkg> <whole> <root> <head> | unmappable <root> <head> <workspace> | config-guard <root> <head>",
                  file=sys.stderr)
            return 1
    except (DiffError, InputError) as exc:
        print(exc, file=sys.stdout if command == "classify" else sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
