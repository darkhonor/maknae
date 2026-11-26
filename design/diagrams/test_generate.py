import re
import unittest
import uuid

import generate

BASE = '''
title = "T"
subtitle = ["s"]
svg_title = "T"
svg_desc = "d"
pitch = 185

[[participant]]
id = "a"
label = "A"
stereo = "«a»"
kind = "untrusted"

[[participant]]
id = "b"
label = "B"
stereo = "«b»"
kind = "trusted"

[[step]]
label = "first"
kind = "call"
from = "a"
to = "b"
evidence = "crates/maknae-kernel/src/task.rs"

[[step]]
label = "second"
kind = "reply"
from = "b"
to = "a"
evidence = "crates/maknae-kernel/src/task.rs"
'''

LIVE = BASE.replace('kind = "call"', 'kind = "call"\nstatus = "live"').replace(
    'kind = "reply"', 'kind = "reply"\nstatus = "live"')


def render(toml_text: str) -> str:
    path = generate.OUT / f"_t_{uuid.uuid4().hex}.toml"
    path.write_text(toml_text)
    try:
        return generate.sequence(path.name)
    finally:
        path.unlink()


def exits(test, toml_text, fragment: str):
    with test.assertRaises(SystemExit) as cm:
        render(toml_text)
    test.assertIn(fragment, str(cm.exception))


def on_step(toml_text: str, n: int, extra: str) -> str:
    """Insert `extra` lines into the n-th (1-based) [[step]] table."""
    parts = toml_text.split("[[step]]\n")
    parts[n] = extra + "\n" + parts[n]
    return "[[step]]\n".join(parts)


class StepIds(unittest.TestCase):
    def test_base_renders(self):
        self.assertTrue(render(BASE).startswith("<svg"))

    def test_step_id_must_match_pattern(self):
        exits(self, on_step(BASE, 1, 'id = "Bad_Id"'), "id 'Bad_Id' must match")

    def test_step_id_partial_match_exits(self):
        exits(self, on_step(BASE, 1, 'id = "a_b"'), "id 'a_b' must match")

    def test_step_id_not_a_string_exits(self):
        exits(self, on_step(BASE, 1, "id = 5"), "id 5 must match")

    def test_unknown_step_kind_exits(self):
        exits(self, BASE.replace('kind = "call"', 'kind = "Ref"'), "unknown kind 'Ref'")

    def test_step_kind_list_exits(self):
        exits(self, BASE.replace('kind = "call"', 'kind = ["x"]'), "unknown kind ['x']")

    def test_missing_step_kind_exits(self):
        exits(self, BASE.replace('kind = "call"\n', ""), "unknown kind None")

    def test_duplicate_step_id_exits(self):
        t = on_step(on_step(BASE, 1, 'id = "x"'), 2, 'id = "x"')
        exits(self, t, "duplicate step id 'x'")

    def test_ids_do_not_render(self):
        self.assertNotIn("zzq-marker", render(on_step(BASE, 1, 'id = "zzq-marker"')))


class Precondition(unittest.TestCase):
    def test_precondition_not_a_string_exits(self):
        exits(self, "precondition = 5\n" + BASE, "precondition must be a str")

    def test_precondition_is_the_first_note(self):
        svg = render('precondition = "PRE-SENTINEL"\n' + on_step(BASE, 1, 'note = "STEP-NOTE"'))
        self.assertIn("Before step 1.", svg)
        self.assertLess(svg.index("PRE-SENTINEL"), svg.index("STEP-NOTE"))
        x = float(re.search(r'<text x="([\d.]+)"[^>]*>PRE-SENTINEL<', svg).group(1))
        self.assertGreater(x, 40 + 14 * 5.5)

    def test_precondition_wider_than_canvas_exits(self):
        exits(self, f'precondition = "{"x" * 400}"\n' + BASE, "precondition does not fit")


class StatusRegression(unittest.TestCase):
    def test_missing_status_still_exits(self):
        exits(self, on_step(BASE, 1, 'status = "live"'), "no status")

    def test_decided_without_adr_exits(self):
        t = on_step(on_step(BASE, 1, 'status = "decided"'), 2, 'status = "live"')
        exits(self, t, "decided cites no ADR")


if __name__ == "__main__":
    unittest.main()
