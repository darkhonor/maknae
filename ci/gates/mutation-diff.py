#!/usr/bin/env python3
"""Pure decisions for the PR-scoped mutation gate (#593). Python 3.11+, stdlib only."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

GIT_ENV = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR",
           "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_LITERAL_PATHSPECS", "GIT_NOGLOB_PATHSPECS",
           "GIT_GLOB_PATHSPECS", "GIT_ICASE_PATHSPECS")
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
BINARY = re.compile(r"^(?:Binary files .* differ|GIT binary patch)$")
ABSENT = re.compile(r"does not exist in|exists on disk, but not in")
MUTANTS_INSTALL = re.compile(r"cargo-mutants\s+--version\s+\S+")
NEXTEST_FILES = (".config/nextest.toml", "ci/gates/mutation-platform.sh")
NEXTEST_CRATES = ("maknae-io", "maknae-sys")
CARGO_CONFIGS = (".cargo/config.toml", ".cargo/config")
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
ALL_FILES = (
    "ci/gates/mutation-oracle.sh",
    "ci/gates/coverage-tiers.sh",
    "ci/gates/mutation-diff.py",
    "rust-toolchain.toml",
)


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


def check_paths(root, base, diff_text):
    named = diff_paths(diff_text)
    done = git(root, "-c", "core.quotePath=true", "diff", "--name-only", "-z", "--no-renames",
               "--diff-filter=d", "--no-ext-diff", base, "HEAD")
    if done.returncode != 0:
        raise ScopeError(f"FAIL: git diff --name-only {base} HEAD failed: {done.stderr.decode().strip()}")
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
        t1 = data["t1"]
        crates = t1["mutants_crates"]
        features = t1.get("mutants_features", {})
        if not (isinstance(crates, list) and isinstance(features, dict)):
            return None
        return set(crates), features
    except (KeyError, TypeError):
        return None


def scope_crates(root, base, head):
    base_sha, head_sha = resolve(root, base), resolve(root, head)
    dirs = workspace_crates(root)

    def read(path):
        return show(root, base_sha, path), show(root, head_sha, path)

    base_tiers, head_tiers = (tiers(text) for text in read("coverage-tiers.toml"))
    mutants = set(head_tiers[0]) if head_tiers else set(dirs)
    selected = set()

    def widen_all():
        selected.update(mutants)

    def owners_of(entry, by_path):
        if by_path:
            return {c for c in mutants if c in dirs and entry.startswith(dirs[c] + "/")}
        return {c for c in mutants if c in dirs and (dirs[c] in entry or Path(dirs[c]).name in entry)}

    if head_tiers is None or base_tiers is None:
        widen_all()
    else:
        selected |= head_tiers[0] - base_tiers[0]
        for crate in set(head_tiers[1]) | set(base_tiers[1]):
            if head_tiers[1].get(crate) != base_tiers[1].get(crate):
                selected.add(crate)

    old, new = read(".cargo/mutants.toml")
    if old != new:
        old_data, new_data = parse_toml(old), parse_toml(new)
        if old_data is None or new_data is None:
            widen_all()
        else:
            for key in set(old_data) | set(new_data):
                if key in ("exclude_globs", "exclude_re"):
                    pair = (old_data.get(key, []), new_data.get(key, []))
                    if not all(isinstance(v, list) and all(isinstance(e, str) for e in v) for v in pair):
                        widen_all()
                        continue
                    for entry in set(pair[0]) ^ set(pair[1]):
                        owners = owners_of(entry, False)
                        selected.update(owners) if owners else widen_all()
                elif old_data.get(key) != new_data.get(key):
                    widen_all()

    old, new = read("ci/gates/mutation-terminated.txt")
    for entry in set((old or "").splitlines()) ^ set((new or "").splitlines()):
        if not entry.strip() or entry.startswith("#"):
            continue
        fields = entry.split("\t")
        owners = owners_of(fields[1], True) if len(fields) == 5 else set()
        selected.update(owners) if owners else widen_all()

    for path in ALL_FILES:
        old, new = read(path)
        if old != new:
            widen_all()

    old, new = read(".github/workflows/ci.yml")
    if set(MUTANTS_INSTALL.findall(old or "")) != set(MUTANTS_INSTALL.findall(new or "")):
        widen_all()

    for path in NEXTEST_FILES:
        old, new = read(path)
        if old != new:
            selected.update(NEXTEST_CRATES)

    for path in CARGO_CONFIGS:
        old, new = read(path)
        if old != new:
            widen_all()

    old, new = read("Cargo.toml")
    if old != new:
        old_data, new_data = parse_toml(old), parse_toml(new)
        if old_data is None or new_data is None or root_compiled(old_data) != root_compiled(new_data):
            widen_all()

    for crate in mutants & set(dirs):
        old, new = read(f"{dirs[crate]}/Cargo.toml")
        old_data, new_data = parse_toml(old), parse_toml(new)
        if old != new and (old_data is None or new_data is None
                           or crate_compiled(old_data) != crate_compiled(new_data)):
            selected.add(crate)
            continue
        scripts = {"build.rs"} | {d.get("package", {}).get("build") for d in (old_data, new_data)
                                  if isinstance(d, dict) and isinstance(d.get("package"), dict)}
        for script in sorted(s for s in scripts if isinstance(s, str)):
            old, new = read(f"{dirs[crate]}/{script}")
            if old != new:
                selected.add(crate)

    return sorted(selected & mutants)


def without(table, keys):
    return {k: v for k, v in table.items() if k not in keys} if isinstance(table, dict) else table


def crate_compiled(manifest):
    data = without(manifest, DEPENDENCY_TABLES)
    if isinstance(data.get("target"), dict):
        targets = {cfg: without(table, DEPENDENCY_TABLES) for cfg, table in data["target"].items()}
        data["target"] = {cfg: table for cfg, table in targets.items() if table != {}}
        if data["target"] == {}:
            del data["target"]
    return data


def root_compiled(manifest):
    data = dict(manifest)
    if isinstance(data.get("workspace"), dict):
        data["workspace"] = without(data["workspace"], ("dependencies",))
    return data


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
        elif len(argv) == 4 and command == "scope":
            print(json.dumps(scope_crates(argv[1], argv[2], argv[3])))
        elif len(argv) == 4 and command == "paths":
            for name in check_paths(argv[1], argv[2], read_diff(argv[3])):
                print(name)
        else:
            print("FAIL: usage: mutation-diff.py changed-lines <diff> | classify <pkg> <diff> "
                  "<whole> <indiff> | scope <root> <base> <head> | paths <root> <base> <diff>",
                  file=sys.stderr)
            return 1
    except (DiffError, ScopeError) as exc:
        print(exc, file=sys.stdout if command == "classify" else sys.stderr)
        return 1
    except OSError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
