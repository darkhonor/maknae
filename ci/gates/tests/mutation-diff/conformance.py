#!/usr/bin/env python3
"""mutation-diff.py's changed lines select exactly the mutants real cargo-mutants 27.1.0 selects
with --in-diff, on diffs made by coverage-tiers.sh's own in_diff_generate."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[4]
GATE = ROOT / "ci/gates/coverage-tiers.sh"
CHANNEL = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
VERSION = "cargo-mutants 27.1.0"
spec = importlib.util.spec_from_file_location("mutation_diff", ROOT / "ci/gates/mutation-diff.py")
md = importlib.util.module_from_spec(spec)
spec.loader.exec_module(md)

LIB = """pub mod other;

pub fn alpha(x: u32) -> u32 {
    let mut t = x + 1;
    t = t * 2;
    t = t - 3;
    t
}

pub fn beta(v: &mut Vec<u32>, x: u32) {
    v.push(x + 1);
    v.push(x * 2);
    v.push(x - 3);
}

pub fn gamma(x: u32) -> bool {
    x > 10 && x < 100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kills() {
        assert_eq!(alpha(4), 7);
        let mut v = Vec::new();
        beta(&mut v, 4);
        assert_eq!(v, [5, 8, 1]);
        assert!(gamma(11) && !gamma(10) && !gamma(100));
        assert_eq!(other::delta(3), 9);
    }
}
"""
OTHER = "pub fn delta(x: u32) -> u32 {\n    let y = x;\n    y * x\n}\n"
BASE = {
    "Cargo.toml": '[package]\nname = "conf"\nversion = "0.1.0"\nedition = "2021"\n',
    ".gitignore": "/target\nCargo.lock\n",
    "src/lib.rs": LIB,
    "src/other.rs": OTHER,
}


def lib(old, new):
    assert old in LIB, old
    return {"src/lib.rs": LIB.replace(old, new, 1)}


def rename_with_edit():
    head = lib("pub mod other;", "pub mod renamed;")
    head["src/lib.rs"] = head["src/lib.rs"].replace("other::delta", "renamed::delta")
    head["src/other.rs"] = None
    head["src/renamed.rs"] = OTHER.replace("y * x", "y * x + 1")
    return head


def mixed():
    head = lib("    v.push(x * 2);\n", "")
    head["src/lib.rs"] = head["src/lib.rs"].replace("x > 10 &&", "x > 11 &&")
    return head


SHAPES = [
    ("one added line", lib("    t = t * 2;\n", "    t = t * 2;\n    t = t + 0;\n"), {}, {}),
    ("a replacement", lib("t = t * 2;", "t = t * 4;"), {}, {}),
    ("a replacement whose - run is longer than its + run",
     lib("    t = t * 2;\n    t = t - 3;\n    t\n", "    t * 2 - 3\n"), {}, {}),
    ("a deletion-only run in a fn body", lib("    v.push(x * 2);\n", ""), {}, {}),
    ("a deletion at a fn's first body line", lib("    v.push(x + 1);\n", ""), {}, {}),
    ("a deletion just before the closing brace", lib("    v.push(x - 3);\n", ""), {}, {}),
    ("a context-only reach into a body", lib("\npub fn beta", "\n// between\npub fn beta"), {}, {}),
    ("a rename with an edit", rename_with_edit(), {}, {}),
    ("a two-file diff",
     {**lib("t = t - 3;", "t = t - 4;"), "src/other.rs": OTHER.replace("y * x", "y + x")}, {}, {}),
    ("a deletion under diff.context=0", lib("    t = t * 2;\n", ""), {"diff.context": "0"}, {}),
    ("a mixed change under GIT_DIFF_OPTS=-u0", mixed(), {}, {"GIT_DIFF_OPTS": "-u0"}),
]


def clean_env(**extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(LLVM_COV="", LLVM_PROFDATA="", RUSTUP_TOOLCHAIN=CHANNEL, **extra)
    return env


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=conformance", "-c",
                    "user.email=conformance@example.invalid", "-c", "commit.gpgsign=false",
                    "-c", "core.hooksPath=/dev/null", *args],
                   env=clean_env(), check=True, capture_output=True)


def write(repo, files):
    for name, text in files.items():
        path = repo / name
        if text is None:
            path.unlink()
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def mutants(repo, *args):
    done = subprocess.run(["cargo", "mutants", "--list", "--json", *args], cwd=repo,
                          env=clean_env(), capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError(f"cargo mutants {' '.join(args)} exited {done.returncode}: {done.stderr}")
    return json.loads(done.stdout) if done.stdout.strip() else []


def generate(repo, base, out, env):
    done = subprocess.run(
        ["bash", "-c", 'source "$1" && root="$2" && in_diff_generate "$3" "$4"', "conformance",
         str(GATE), str(repo), base, str(out)],
        env=clean_env(**env), capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError(f"in_diff_generate exited {done.returncode}: {done.stderr}")
    return out.read_text()


def check(name, head, config, env, scratch):
    repo = scratch / "repo"
    write(repo, BASE)
    git(repo, "init", "-q")
    for key, value in config.items():
        git(repo, "config", key, value)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    base = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], env=clean_env(),
                          check=True, capture_output=True, text=True).stdout.strip()
    write(repo, head)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "head")
    diff = generate(repo, base, scratch / "in.diff", env)
    if not diff.strip():
        return ["in_diff_generate wrote an empty diff"], 0
    whole = mutants(repo)
    if not whole:
        return ["the whole listing is empty"], 0
    selected = sorted(m["name"] for m in mutants(repo, "--in-diff", str(scratch / "in.diff")))
    marked = sorted(m["name"] for m in md.overlapping("conf", md.changed_lines(diff), whole))
    problems = []
    if marked != selected:
        problems.append(f"parser-only {sorted(set(marked) - set(selected))}, "
                        f"cargo-mutants-only {sorted(set(selected) - set(marked))}")
    context_only = name.startswith("a context-only")
    if bool(selected) == context_only:
        problems.append(f"expected {'no' if context_only else 'some'} selected mutants, got {selected}")
    if "rename" in name and "rename to src/renamed.rs" not in diff:
        problems.append("the diff does not record the rename")
    if "GIT_DIFF_OPTS" in name and not any(" in beta" in n for n in selected):
        problems.append(f"the deletion in beta selected none of its mutants: {selected}")
    if problems:
        problems.append("diff:\n" + diff)
    return problems, len(selected)


def main():
    if shutil.which("cargo-mutants") is None:
        print("FAIL: conformance needs cargo-mutants")
        return 1
    version = subprocess.run(["cargo", "mutants", "--version"], env=clean_env(),
                             capture_output=True, text=True).stdout.strip()
    if version != VERSION:
        print(f"FAIL: conformance needs {VERSION}, found {version or 'nothing'}")
        return 1
    failures = 0
    for name, head, config, env in SHAPES:
        with tempfile.TemporaryDirectory() as directory:
            try:
                result = check(name, head, config, env, Path(directory))
            except (RuntimeError, subprocess.CalledProcessError, md.DiffError) as exc:
                result = ([str(exc)], 0)
        problems, count = result
        if problems:
            failures += 1
            print(f"FAIL: {name}: " + "\n  ".join(problems))
        else:
            print(f"ok: {name}: {count} mutants selected")
    if failures:
        print(f"{failures} of {len(SHAPES)} shapes do not conform")
        return 1
    print(f"PASS: {len(SHAPES)} diff shapes conform to {VERSION}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
