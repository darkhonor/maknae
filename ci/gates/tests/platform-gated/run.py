#!/usr/bin/env python3
"""Fixture trees for ci/gates/platform-gated.py."""
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[4]
os.environ["RUSTUP_TOOLCHAIN"] = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
SCRIPT = ROOT / "ci/gates/platform-gated.py"
spec = importlib.util.spec_from_file_location("platform_gated", SCRIPT)
pg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pg)

LINUX_ABSENT = "macos_fd_path|apple_only|macos_kept|nowhere|feature_off|macos_not_test"
DARWIN_ABSENT = "linux_fd_path|multi_line|nowhere|feature_off|default_on"
LINUX_FILES = "|^crates/maknae-sys/src/macos\\.rs:|^crates/maknae-sys/src/macos/inner\\.rs:"
SYSCALL = """\
#[cfg(target_os = "linux")]
pub(crate) fn linux_fd_path() -> u8 { 1 }
#[cfg(target_os = "macos")]
pub(crate) fn macos_fd_path() -> u8 { 2 }
#[cfg(target_vendor = "apple")]
fn apple_only() -> u8 { 3 }
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn nowhere() {}
#[cfg(all(target_os = "macos", feature = "seam"))]
fn macos_kept() {}
#[cfg(all(target_os = "linux", feature = "absent"))]
fn feature_off() {}
#[cfg(all(target_os = "linux", feature = "deep"))]
fn default_on() -> u8 { 6 }
#[cfg(all(target_os = "macos", not(test)))]
fn macos_not_test() {}
#[cfg(target_os = "linux")]
#[test_case(1)]
fn linux_case(_: u8) {}
#[tokio::test]
async fn tokio_case() {}
fn statements() -> u8 {
    #[cfg(target_os = "linux")]
    let x = 1;
    #[cfg(not(target_os = "linux"))]
    let x = 2;
    x
}
#[cfg(any(target_os = "macos", test))]
fn test_widened() -> u8 { 4 }
/// Doc lines and a split attribute.
#[cfg(
    target_os = "linux"
)]
/// More doc.
#[inline]
pub(crate) const unsafe extern "C" fn multi_line() -> u8 { 5 }
#[cfg(unix)]
fn portable() -> &'static str { "{" }
#[cfg_attr(docsrs, doc(cfg(feature = "x")))]
fn documented() {}
fn typed() -> impl Fn(u8) -> u8 {
    let f: unsafe extern "C" fn() = noop;
    let _ = f;
    |x| x
}
#[cfg(all(test, unix))]
mod helpers {
    #[cfg(target_os = "linux")]
    fn linux_helper() {}
}
#[cfg(target_os = "linux")]
#[test]
fn linux_test() {}
impl Holder {
    fn shared(&self) -> char { '}' }
}
struct Holder;
"""


def platform_script(linux, linux_files, darwin, darwin_files):
    script = (ROOT / "ci/gates/mutation-platform.sh").read_text()
    arms = iter([(linux, linux_files), (darwin, darwin_files)])

    def arm(match):
        absent, files = next(arms)
        return f"{match.group(1)}absent='{absent}'{match.group(2)}inactive_files='{files}';;"
    script, count = re.subn(r"((?:Linux|Darwin)\)\s*)absent='[^']*'(\s*)inactive_files='[^']*';;", arm, script)
    assert count == 2
    return script


class Tree:
    def __init__(self, directory):
        self.root = Path(directory)
        self.files = {
            "Cargo.toml": '[workspace]\nmembers = ["crates/*"]\nresolver = "2"\n',
            "coverage-tiers.toml": '[t1]\nmutants_crates = ["maknae-io", "maknae-sys", "other"]\n'
                                   'mutants_features = { maknae-io = ["seam"] }\n',
            ".cargo/mutants.toml": 'exclude_globs = ["crates/maknae-io/src/skipped.rs"]\n',
            "ci/gates/coverage-tiers.sh": (
                '    if [ "$cname" = "maknae-io" ] || [ "$cname" = "maknae-sys" ]; then\n'
                '      if ! native_exclusion="$(bash "$here/mutation-platform.sh")"; then\n'),
            "ci/gates/mutation-platform.sh": platform_script(LINUX_ABSENT, LINUX_FILES, DARWIN_ABSENT, ""),
            "crates/maknae-io/src/lib.rs": "mod syscall;\nmod skipped;\nmod strategy;\n#[cfg(test)]\nmod tests;\n",
            "crates/maknae-io/src/syscall.rs": SYSCALL,
            "crates/maknae-io/src/skipped.rs": '#[cfg(target_os = "linux")]\nfn excluded_linux() {}\n',
            "crates/maknae-io/src/strategy.rs": (
                'fn neutral() {}\nextern "C" {\n    #[cfg(target_os = "linux")]\n    fn linux_decl();\n}\n'
                '#[cfg(target_os = "macos")]\nunsafe extern "C" {\n    fn macos_decl();\n}\n'),
            "crates/maknae-io/src/tests.rs": '#[cfg(windows)]\nfn ignored() {}\n',
            "crates/maknae-sys/src/lib.rs": '#![cfg(unix)]\n#[cfg(target_os = "macos")]\nmod macos;\n',
            "crates/maknae-sys/src/macos.rs": '#[cfg(target_os = "linux")]\nfn unlisted_inner() {}\nmod inner;\n',
            "crates/maknae-sys/src/macos/inner.rs": "fn deep() {}\n",
            "crates/other/src/lib.rs": "pub fn neutral() {}\n",
        }
        for crate in ("maknae-io", "maknae-sys", "other"):
            self.files[f"crates/{crate}/Cargo.toml"] = (
                f'[package]\nname = "{crate}"\nversion = "0.0.0"\nedition = "2021"\n\n'
                '[features]\ndefault = ["base"]\nbase = ["deep"]\ndeep = []\nseam = []\nabsent = []\n')

    def write(self):
        for name, text in self.files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return self.root

    def run(self):
        self.write()
        return subprocess.run([sys.executable, str(SCRIPT), "check", str(self.root)],
                              text=True, capture_output=True)


class Evaluator(unittest.TestCase):
    def value(self, text, platform, test=True, features=()):
        toks = pg.lex(text, "fixture")
        return pg.evaluate(pg.parse_cfg(toks, "fixture", 1), platform, test, set(features), "fixture:1")

    def test_leaves(self):
        cases = [
            ("test", (True, True), {}), ("unix", (True, True), {}),
            ('target_os = "linux"', (True, False), {}), ('target_os = "macos"', (False, True), {}),
            ('target_vendor = "apple"', (False, True), {}),
            ('feature = "seam"', (True, True), {"features": ["seam"]}),
            ('feature = "seam"', (False, False), {}),
            ('not(target_os = "linux")', (False, True), {}),
            ('all(unix, target_os = "macos")', (False, True), {}),
            ('any(target_os = "macos", test)', (True, True), {}),
        ]
        for text, (linux, macos), extra in cases:
            self.assertEqual((self.value(text, "linux", **extra), self.value(text, "macos", **extra)),
                             (linux, macos), text)
        self.assertFalse(self.value("test", "linux", test=False))

    def test_unknown_predicates_fail(self):
        for text in ("windows", 'target_vendor = "pc"', 'target_os = "freebsd"', 'target_family = "unix"', "debug_assertions",
                     'all(unix, target_arch = "x86_64")'):
            with self.assertRaisesRegex(pg.GateError, "unsupported cfg predicate"):
                self.value(text, "linux")


class Derivation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tree = Tree(self.tmp.name)

    def derived(self):
        return {(g.file, g.kind, g.name, tuple(sorted(g.active)))
                for g in pg.derive(self.tree.write())}

    def assertFails(self, *needles):
        result = self.tree.run()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for needle in needles:
            self.assertIn(needle, result.stdout)
        return result.stdout

    def test_derived_set_is_exact(self):
        sc = "crates/maknae-io/src/syscall.rs"
        self.assertEqual(self.derived(), {
            (sc, "fn", "linux_fd_path", ("linux",)),
            (sc, "fn", "macos_fd_path", ("macos",)),
            (sc, "fn", "apple_only", ("macos",)),
            (sc, "fn", "nowhere", ()),
            (sc, "fn", "feature_off", ()),
            (sc, "fn", "default_on", ("linux",)),
            (sc, "fn", "macos_not_test", ("macos",)),
            (sc, "fn", "macos_kept", ("macos",)),
            (sc, "fn", "multi_line", ("linux",)),
            ("crates/maknae-sys/src/macos.rs", "mod-file", "macos", ("macos",)),
            ("crates/maknae-sys/src/macos/inner.rs", "mod-file", "inner", ("macos",)),
        })

    def test_consistent_tree_passes(self):
        result = self.tree.run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_name_missing_from_inactive_platform_fails(self):
        self.tree.files["ci/gates/mutation-platform.sh"] = self.tree.files[
            "ci/gates/mutation-platform.sh"].replace("|apple_only", "")
        self.assertFails("syscall.rs:6: fn apple_only is inactive on linux")

    def test_name_listed_where_active_fails(self):
        self.tree.files["ci/gates/mutation-platform.sh"] = self.tree.files[
            "ci/gates/mutation-platform.sh"].replace(DARWIN_ABSENT, DARWIN_ABSENT + "|macos_fd_path")
        self.assertFails("fn macos_fd_path is active on macos but excluded")

    def test_stale_absent_name_fails(self):
        self.tree.files["ci/gates/mutation-platform.sh"] = self.tree.files[
            "ci/gates/mutation-platform.sh"].replace(LINUX_ABSENT, LINUX_ABSENT + "|ghost_fn")
        self.assertFails("Linux absent list names ghost_fn, which is not a platform-gated fn inactive on linux")

    def test_absent_name_colliding_with_an_ungated_fn_fails(self):
        self.tree.files["ci/gates/mutation-platform.sh"] = self.tree.files[
            "ci/gates/mutation-platform.sh"].replace(DARWIN_ABSENT, DARWIN_ABSENT + "|statements")
        self.assertFails("Darwin absent list names statements, which is not a platform-gated fn inactive on macos")

    def test_stale_inactive_file_fails(self):
        self.tree.files["ci/gates/mutation-platform.sh"] = platform_script(
            LINUX_ABSENT, LINUX_FILES, DARWIN_ABSENT, "|^crates/maknae-io/src/strategy\\.rs:")
        self.assertFails("Darwin inactive_files names crates/maknae-io/src/strategy.rs, "
                         "which is not a platform-gated module file inactive on macos")

    def test_path_inside_cfg_attr_fails(self):
        self.tree.files["crates/maknae-io/src/lib.rs"] += '#[cfg_attr(unix, path = "strategy.rs")]\nmod elsewhere;\n'
        self.assertFails("crates/maknae-io/src/lib.rs:6: path inside cfg_attr is not followed")

    def test_unknown_predicate_fails_with_location(self):
        self.tree.files["crates/maknae-io/src/strategy.rs"] = 'fn a() {}\n#[cfg(windows)]\nfn b() {}\n'
        self.assertFails("crates/maknae-io/src/strategy.rs:2", "unsupported cfg predicate `windows`")

    def test_gated_fn_in_filtered_crate_outside_syscall_fails(self):
        self.tree.files["crates/maknae-io/src/strategy.rs"] = (
            '#[cfg(target_os = "linux")]\npub(crate) fn linux_probe_scratch() -> u8 { 1 }\n')
        self.assertFails("strategy.rs:2: fn linux_probe_scratch is platform-gated outside")

    def test_gated_fn_in_unfiltered_crate_fails(self):
        self.tree.files["crates/other/src/lib.rs"] = '#[cfg(target_os = "macos")]\nfn macos_other() {}\n'
        self.assertFails("fn macos_other is platform-gated in other, which the native mutation filter does not cover")

    def test_gated_mod_file_not_listed_fails(self):
        self.tree.files["crates/maknae-io/src/lib.rs"] += '#[cfg(target_os = "linux")]\nmod scratch;\n'
        self.tree.files["crates/maknae-io/src/scratch.rs"] = "fn inside() {}\n"
        self.assertFails("crates/maknae-io/src/scratch.rs:1: mod-file scratch is inactive on macos "
                         "but missing from mutation-platform.sh's Darwin inactive_files")

    def test_gated_impl_with_fn_fails(self):
        self.tree.files["crates/maknae-io/src/syscall.rs"] += (
            '#[cfg(target_os = "linux")]\nimpl Holder {\n    fn linux_fd_path(&self) {}\n}\n')
        self.assertFails("impl impl Holder is a platform-gated block containing items",
                         "fn linux_fd_path is platform-gated inside an impl")

    def test_gated_fn_inside_ungated_impl_fails(self):
        self.tree.files["crates/maknae-io/src/syscall.rs"] += (
            'impl Holder {\n    #[cfg(target_os = "macos")]\n    fn macos_fd_path(&self) {}\n}\n')
        self.assertFails("fn macos_fd_path is platform-gated inside an impl")

    def test_gated_inline_mod_with_fn_fails(self):
        self.tree.files["crates/maknae-io/src/syscall.rs"] += (
            '#[cfg(target_os = "macos")]\nmod native {\n    fn inner() {}\n}\n')
        self.assertFails("inline-mod native is a platform-gated block containing items")

    def test_wildcard_exclude_glob_fails(self):
        self.tree.files[".cargo/mutants.toml"] = 'exclude_globs = ["crates/maknae-io/src/*.rs"]\n'
        self.assertFails("is a pattern; extend the matcher deliberately")

    def test_path_attribute_fails(self):
        self.tree.files["crates/maknae-io/src/lib.rs"] += '#[path = "strategy.rs"]\nmod elsewhere;\n'
        self.assertFails("#[path] on mod elsewhere is not followed")

    def test_unparseable_filter_guard_fails(self):
        self.tree.files["ci/gates/coverage-tiers.sh"] = 'bash "$here/mutation-platform.sh"\n'
        self.assertFails("no crate list guards the mutation-platform.sh call")

    def test_broken_parser_cannot_pass(self):
        self.tree.files["crates/maknae-io/src/syscall.rs"] = "fn nothing() {}\n"
        self.tree.files["crates/maknae-sys/src/lib.rs"] = ""
        self.assertFails("derived set lacks linux_fd_path", "derived set lacks macos_fd_path",
                         "derived set lacks crates/maknae-sys/src/macos.rs")

    def test_gated_fn_below_the_top_level_of_syscall_fails(self):
        self.tree.files["crates/maknae-io/src/syscall.rs"] += (
            'mod inner {\n    #[cfg(target_os = "macos")]\n    pub fn macos_fd_path() {}\n}\n')
        self.assertFails("fn inner::macos_fd_path is platform-gated below the top level")

    def test_filter_regex_must_match_the_unit_form(self):
        script = self.tree.files["ci/gates/mutation-platform.sh"]
        self.assertIn("( ->| with )", script)
        self.tree.files["ci/gates/mutation-platform.sh"] = script.replace("( ->| with )", "( ->)")
        self.assertFails("syscall.rs:1:1: replace nowhere with () is not excluded on linux")

    def test_filter_regex_must_exclude_listed_names(self):
        script = self.tree.files["ci/gates/mutation-platform.sh"]
        self.tree.files["ci/gates/mutation-platform.sh"] = script.replace('"$absent"', '"none"')
        self.assertFails("replace linux_fd_path -> T with x is not excluded on macos")

    def test_cfg_inside_cfg_attr_fails(self):
        self.tree.files["crates/maknae-io/src/strategy.rs"] = (
            '#[cfg_attr(target_os = "linux", cfg(test))]\nfn hidden() {}\n')
        self.assertFails("crates/maknae-io/src/strategy.rs:1: cfg inside cfg_attr")

    def test_gated_fn_nested_in_a_fn_body_fails(self):
        self.tree.files["crates/maknae-io/src/strategy.rs"] = (
            'fn outer() {\n    let _ = 1;\n    #[cfg(target_os = "linux")]\n    fn nested() {}\n}\n')
        self.assertFails("crates/maknae-io/src/strategy.rs:3: cfg-gated fn inside a body or initializer")

    def test_gated_fn_nested_in_an_initializer_fails(self):
        self.tree.files["crates/maknae-io/src/strategy.rs"] = (
            'const X: u8 = {\n    #[cfg(target_os = "macos")]\n    #[inline]\n    pub fn nested() -> u8 { 1 }\n    1\n};\n')
        self.assertFails("crates/maknae-io/src/strategy.rs:2: cfg-gated fn inside a body or initializer")

    def test_brace_in_type_generics_fails(self):
        self.tree.files["crates/maknae-io/src/strategy.rs"] = (
            'fn a() {}\nstruct S<const N: usize = { 1 }> {\n    x: [u8; N],\n}\n')
        self.assertFails("crates/maknae-io/src/strategy.rs:2: '{' inside the generics of struct S")

    def test_mismatched_delimiter_names_file_and_line(self):
        self.tree.files["crates/maknae-io/src/strategy.rs"] = "fn a() {}\nfn b() {\n    ( ]\n}\n"
        self.assertFails("crates/maknae-io/src/strategy.rs:3: mismatched ']'")

    def test_unbalanced_delimiter_names_file_and_line(self):
        self.tree.files["crates/maknae-io/src/strategy.rs"] = "fn a() {}\nfn b() {\n"
        self.assertFails("crates/maknae-io/src/strategy.rs:2: unbalanced '{'")

    def test_item_running_off_its_module_names_file_and_line(self):
        self.tree.files["crates/maknae-io/src/strategy.rs"] = "fn a() {}\nconst B: u8 = 1\n"
        self.assertFails("crates/maknae-io/src/strategy.rs:2: item runs off the end of its module")

    def test_unknown_test_attribute_fails(self):
        self.tree.files["crates/maknae-io/src/strategy.rs"] = "#[harness::test]\nfn t() {}\n"
        self.assertFails("crates/maknae-io/src/strategy.rs:1: unknown test attribute `harness::test`")

    def test_unsupported_target_kind_fails(self):
        self.tree.files["crates/other/Cargo.toml"] += '\n[lib]\ncrate-type = ["cdylib"]\n'
        self.assertFails("other: target other has kind cdylib")

    def test_match_guard_near_miss_is_not_excluded(self):
        script = self.tree.files["ci/gates/mutation-platform.sh"]
        loose, count = re.subn(r"printf '[^\n]*", "printf '^crates/maknae-io/src/syscall\\.rs:[0-9]+:[0-9]+: "
                               ".* (%s)( ->| with |$)%s\\n' \"$absent\" \"$inactive_files\"", script)
        self.assertEqual(count, 1)
        self.tree.files["ci/gates/mutation-platform.sh"] = loose
        self.assertFails("replace match guard a == linux_fd_path with true in linux_fd_path_neighbour "
                         "is excluded on macos")

    def test_nested_item_inside_a_gated_fn_fails(self):
        self.tree.files["crates/maknae-io/src/syscall.rs"] += (
            '#[cfg(target_os = "macos")]\nfn macos_outer() {\n    let _ = 1;\n    fn helper() {}\n}\n')
        self.assertFails("fn inside platform-gated fn macos_outer")

    def test_nested_item_inside_a_gated_inline_mod_fails(self):
        self.tree.files["crates/maknae-io/src/syscall.rs"] += (
            '#[cfg(target_os = "macos")]\nmod native {\n    impl super::Holder {}\n}\n')
        self.assertFails("inline-mod native is a platform-gated block containing items")

    def test_gated_fn_nested_in_a_static_initializer_fails(self):
        self.tree.files["crates/maknae-io/src/strategy.rs"] = (
            'static X: u8 = {\n    #[cfg(target_os = "linux")]\n    fn nested() -> u8 { 1 }\n    1\n};\n')
        self.assertFails("crates/maknae-io/src/strategy.rs:2: cfg-gated fn inside a body or initializer")

    def test_gated_mod_nested_in_a_fn_body_fails(self):
        self.tree.files["crates/maknae-io/src/strategy.rs"] = (
            'fn outer4() {\n    #[cfg(target_os = "linux")]\n    mod m {\n        pub fn x() {}\n    }\n}\n')
        self.assertFails("crates/maknae-io/src/strategy.rs:2: cfg-gated mod inside a body or initializer")

    def test_cfg_attr_gated_impl_nested_in_a_fn_body_fails(self):
        self.tree.files["crates/maknae-io/src/strategy.rs"] = (
            'struct Q;\nfn outer4() {\n    #[cfg_attr(unix, cfg(target_os = "macos"))]\n'
            '    impl Q {\n        fn y() {}\n    }\n}\n')
        self.assertFails("crates/maknae-io/src/strategy.rs:3: cfg-gated impl inside a body or initializer")

    def test_gated_trait_nested_in_a_fn_body_fails(self):
        self.tree.files["crates/maknae-io/src/strategy.rs"] = (
            'fn outer4() {\n    #[cfg(target_os = "macos")]\n    pub(crate) unsafe trait T {}\n}\n')
        self.assertFails("crates/maknae-io/src/strategy.rs:2: cfg-gated trait inside a body or initializer")


if __name__ == "__main__":
    unittest.main()
