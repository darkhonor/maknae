#!/usr/bin/env python3
"""The panic strategy must stay `unwind` (#544).

usage: panic_check.py static <root> <surfaces.tsv>
       panic_check.py proof <root>

`surfaces.tsv` lists build-surface files, one `<path>\\t<continuation-joined copy>` per line.
"""
import json
import os
import re
import shlex
import signal
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None

PANIC_KEY = re.compile(r"panic\s*=")
PROFILE_ENV = re.compile(r"CARGO_PROFILE_\w+_PANIC\b")
CARGO_HOME = re.compile(r"(?<![\w$.])(?<!\$\{)CARGO_HOME\b|\$\{CARGO_HOME:?=")
CONFIG_FLAG = re.compile(r"--config(?:\s+|=)")
REFUSED = ("panic-abort-tests", "panic_immediate_abort", "immediate-abort")
CARGO_CONFIG = re.compile(r"(?:^|/)\.cargo/config$", re.IGNORECASE)
SUCCESS = "panic boundary: unwind; operand Indeterminate; composition Deny"
EXAMPLE = "panic_boundary"
GIT_ENV = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR",
           "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_LITERAL_PATHSPECS", "GIT_NOGLOB_PATHSPECS",
           "GIT_GLOB_PATHSPECS", "GIT_ICASE_PATHSPECS", "GIT_GRAFT_FILE")


def git_env():
    env = {k: v for k, v in os.environ.items() if k not in GIT_ENV}
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    return env


def value_after(line, end):
    rest = line[end:].lstrip("\"' \t:?+=").split()
    return rest[0].strip("\"'\\") if rest else ""


def profile_panics(value, where):
    if isinstance(value, dict):
        for key, item in value.items():
            here = f"{where}.{key}"
            if key == "panic":
                yield here, item
            else:
                yield from profile_panics(item, here)


def toml_findings(root, names):
    found, read = [], 0
    for name in names:
        if not (name.lower().endswith(".toml") or CARGO_CONFIG.search(name)):
            continue
        try:
            parsed = tomllib.loads((root / name).read_text())
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
            found.append(f"{name}: cannot be read as TOML ({e})")
            continue
        read += 1
        for where, value in profile_panics(parsed.get("profile"), "profile"):
            if value != "unwind":
                found.append(f"{name}: {where} = {value!r}; only \"unwind\" is allowed")
    if read == 0:
        found.append("no tracked TOML file was read; a scan of nothing is not a pass")
    return found


def root_pins(root):
    try:
        profile = tomllib.loads((root / "Cargo.toml").read_text()).get("profile", {})
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        return [f"Cargo.toml: cannot be read as TOML ({e})"]
    return [f"Cargo.toml: [profile.{name}] must pin panic = \"unwind\""
            for name in ("dev", "release")
            if not isinstance(profile.get(name), dict) or profile[name].get("panic") != "unwind"]


def config_argument(line, end):
    try:
        words = shlex.split(line[end:])
    except ValueError:
        return None
    return words[0] if words else None


def config_keys(value, where, wanted):
    if isinstance(value, dict):
        for key, item in value.items():
            here = f"{where}.{key}" if where else key
            if key == wanted:
                yield here
            yield from config_keys(item, here, wanted)


def inline_config_findings(argument):
    if argument is None:
        return ["passes a --config argument the gate cannot read"]
    try:
        parsed = tomllib.loads(argument)
    except tomllib.TOMLDecodeError:
        return [f"passes --config {argument!r}, a file cargo would load unchecked"]
    found = [f"passes --config {argument!r}, whose include cargo would load unchecked"] if "include" in parsed else []
    found += [f"passes --config {argument!r}, which sets {where}; rustflags can change the panic strategy"
              for where in config_keys(parsed, "", "rustflags")]
    found += [f"passes --config {argument!r}, setting {where} to {value!r}; only unwind is allowed"
              for where, value in profile_panics(parsed.get("profile"), "profile") if value != "unwind"]
    return found


def line_findings(where, line):
    for key in (PANIC_KEY, PROFILE_ENV):
        for match in key.finditer(line):
            value = value_after(line, match.end())
            if value != "unwind":
                yield f"{where}: sets the panic strategy to {value!r}; only unwind is allowed"
    for refused in REFUSED:
        if refused in line:
            yield f"{where}: names {refused}"
    if CARGO_HOME.search(line):
        yield f"{where}: sets CARGO_HOME, whose config.toml cargo would load unchecked"
    for match in CONFIG_FLAG.finditer(line):
        for finding in inline_config_findings(config_argument(line, match.end())):
            yield f"{where}: {finding}"


def surface_findings(listing):
    found, read = [], 0
    for entry in listing.read_text().splitlines():
        path, joined = entry.split("\t")
        read += 1
        for number, line in enumerate(Path(joined).read_text(errors="strict").splitlines(), 1):
            found.extend(line_findings(f"{path}: logical line {number}", line))
    if read == 0:
        found.append("no build-surface file was scanned; a scan of nothing is not a pass")
    return found


def static(root, listing):
    if tomllib is None:
        return ["python3 >= 3.11 is required (stdlib tomllib)"]
    listed = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, env=git_env())
    if listed.returncode != 0:
        return [f"git ls-files failed under {root}: {listed.stderr.decode().strip()}"]
    names = [n for n in listed.stdout.decode().split("\0") if n]
    return root_pins(root) + toml_findings(root, names) + surface_findings(listing)


def proof(root):
    build = subprocess.run(
        ["cargo", "build", "--locked", "--release", "-p", "maknae-security", "--example", EXAMPLE,
         "--message-format=json-render-diagnostics"],
        cwd=root, capture_output=True, text=True)
    sys.stderr.write(build.stderr)
    if build.returncode != 0:
        return [f"the release build of the {EXAMPLE} example failed (exit {build.returncode})"]
    executables = []
    for line in build.stdout.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("reason") == "compiler-artifact" and record.get("target", {}).get("name") == EXAMPLE:
            executables.append(record.get("executable"))
    if len(executables) != 1 or not executables[0]:
        return [f"the build reported {executables!r}, not exactly one {EXAMPLE} executable"]
    run = subprocess.run([executables[0]], capture_output=True, text=True)
    sys.stderr.write(run.stderr)
    if run.returncode < 0:
        name = signal.Signals(-run.returncode).name
        return [f"the release-built boundary died on {name} (signal {-run.returncode}): "
                "the release profile does not unwind"]
    if run.returncode != 0 or run.stdout.strip() != SUCCESS:
        return [f"the release-built boundary exited {run.returncode} with {run.stdout.strip()!r}"]
    print(run.stdout.strip())
    return []


def main(argv):
    if len(argv) == 4 and argv[1] == "static":
        found = static(Path(argv[2]), Path(argv[3]))
    elif len(argv) == 3 and argv[1] == "proof":
        found = proof(Path(argv[2]))
    else:
        print("FAIL panic-strategy: usage: panic_check.py static <root> <surfaces.tsv> | proof <root>")
        return 2
    for finding in found:
        print(f"FAIL panic-strategy: {finding}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
