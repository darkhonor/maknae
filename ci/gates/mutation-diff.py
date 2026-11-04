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

GIT_ENV = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR",
           "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_LITERAL_PATHSPECS", "GIT_NOGLOB_PATHSPECS",
           "GIT_GLOB_PATHSPECS", "GIT_ICASE_PATHSPECS", "GIT_GRAFT_FILE")
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
BINARY = re.compile(r"^(?:Binary files .* differ|GIT binary patch)$")
ABSENT = re.compile(r"does not exist in|exists on disk, but not in")
SOURCE_DIRS = ("src", "tests", "benches", "examples")
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


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


def workspace_crates(root):
    env = {k: v for k, v in git_env().items() if k not in ("LLVM_COV", "LLVM_PROFDATA")}
    done = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1",
         "--manifest-path", str(Path(root) / "Cargo.toml")],
        capture_output=True, env=env, check=False)
    if done.returncode != 0:
        raise ScopeError("FAIL: cargo metadata failed: " + done.stderr.decode().strip())
    crates = {}
    for package in json.loads(done.stdout)["packages"]:
        manifest = Path(package["manifest_path"]).resolve()
        crates[package["name"]] = manifest.parent.relative_to(Path(root).resolve()).as_posix()
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


def scope_crates(root, base, head, workspace=None):
    base_sha, head_sha = resolve(root, base), resolve(root, head)
    dirs = workspace_crates(workspace or root)
    head_tiers = tiers(show(root, head_sha, "coverage-tiers.toml"))
    mutants = head_tiers if head_tiers is not None else set(dirs)
    docs_only = affected().docs_only
    script_dirs = {}
    for crate in sorted(mutants & set(dirs)):
        for sha in (base_sha, head_sha):
            present = lambda path, sha=sha: show(root, sha, path) is not None
            for script in build_scripts(root, sha, dirs[crate], present):
                path = script_path(dirs[crate], script)
                script_dirs.setdefault(crate, set()).add("." if path is None else posixpath.dirname(path))
    selected = set()
    for path in changed_names(root, base_sha, head_sha):
        if docs_only(path) or path == "Cargo.lock" or dependency_only(root, base_sha, head_sha, path):
            continue
        selected.update(c for c, found in script_dirs.items() if any(within(path, d) for d in found))
        owner = owner_of(path, dirs)
        nested = owner is not None and dirs[owner] != "."
        rel = path[len(dirs[owner]) + 1:] if nested else path
        if owner is not None and rel.endswith(".rs") and rel.split("/")[0] in SOURCE_DIRS:
            continue
        if not nested:
            selected.update(mutants)
        elif owner in mutants:
            selected.add(owner)
    return sorted(selected & mutants)


def unmappable(root, head, workspace):
    sha = resolve(root, head)
    dirs = workspace_crates(workspace)
    head_tiers = tiers(show(root, sha, "coverage-tiers.toml"))
    mutants = sorted((head_tiers if head_tiers is not None else set(dirs)) & set(dirs))
    listing = git(root, "ls-tree", "-r", "-z", "--full-tree", sha)
    if listing.returncode != 0:
        raise ScopeError(f"FAIL: git ls-tree {sha} failed: {listing.stderr.decode().strip()}")
    paths, links = set(), []
    for record in listing.stdout.split(b"\0"):
        if not record:
            continue
        meta, _, raw = record.partition(b"\t")
        paths.add(raw.decode())
        if meta.split(b" ")[0] == b"120000":
            links.append(raw.decode())
    tree = Path(workspace).resolve()
    for crate in mutants:
        directory = dirs[crate]
        for link in sorted(links):
            target = os.path.relpath(os.path.realpath(tree / link), tree)
            if within(link, directory) or within(target, directory) or within(directory, target):
                return (f"FAIL: --in-diff: symlink {link} in mutation crate {crate}; in-diff mapping "
                        "cannot follow aliases — use the whole-package run")
        for script in build_scripts(root, sha, directory, paths.__contains__):
            path = script_path(directory, script)
            owner = None if path is None else owner_of(path, dirs)
            rel = path if owner is None or dirs[owner] == "." else path[len(dirs[owner]) + 1:]
            if path is None or (owner is not None and rel.split("/")[0] in SOURCE_DIRS):
                return (f"FAIL: --in-diff: build script {path or script} of mutation crate {crate} "
                        "lies inside a diff-mapped directory — use the whole-package run")
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
        elif len(argv) == 4 and command == "unmappable":
            problem = unmappable(*argv[1:])
            if problem:
                print(problem)
                return 1
        else:
            print("FAIL: usage: mutation-diff.py changed-lines <diff> | classify <pkg> <diff> "
                  "<whole> <indiff> | scope <root> <base> <head> [<workspace>] | paths <root> <base> "
                  "<diff> [<head>] | history <root> | snapshot <root> <rev> <dest> | "
                  "unmappable <root> <head> <workspace>",
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
