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


THIRD = '''
[[step]]
label = "third"
kind = "call"
from = "a"
to = "b"
evidence = "crates/maknae-kernel/src/task.rs"
'''


def ids(toml_text: str) -> str:
    """Give every step an id s1, s2, …"""
    parts = toml_text.split("[[step]]\n")
    return "[[step]]\n".join([parts[0]] + [f'id = "s{n}"\n' + t for n, t in enumerate(parts[1:], 1)])


def frag(operator="loop", guard="until done", first="s1", last="s2", **extra) -> str:
    rows = [f'operator = "{operator}"', f'guard = "{guard}"', f'first = "{first}"', f'last = "{last}"']
    rows += [f"{k} = {v}" for k, v in extra.items()]
    return "\n[[fragment]]\n" + "\n".join(rows) + "\n"


def frag_rects(svg: str) -> dict:
    out = {}
    for m in re.finditer(r'<rect data-frag="(\d+)" x="([-\d.]+)" y="([-\d.]+)" '
                         r'width="([-\d.]+)" height="([-\d.]+)"', svg):
        out[int(m.group(1))] = tuple(float(v) for v in m.groups()[1:])
    return out


def text_y(svg: str, content: str) -> float:
    return float(re.search(r'<text x="[-\d.]+" y="([-\d.]+)"[^>]*>' + re.escape(content), svg).group(1))


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


class FragmentValidation(unittest.TestCase):
    def test_fragment_unknown_key_exits(self):
        exits(self, ids(BASE) + frag(colour='"x"'), "fragment 1: unknown key 'colour'")

    def test_fragment_unknown_operator_exits(self):
        exits(self, ids(BASE) + frag(operator="alt"), "operator 'alt' is not loop or opt")

    def test_fragment_empty_guard_exits(self):
        exits(self, ids(BASE) + frag(guard="  "), "guard must be a non-empty string")

    def test_fragment_unknown_end_exits(self):
        exits(self, ids(BASE) + frag(first="nope"), "first 'nope' names no step")

    def test_fragment_first_after_last_exits(self):
        exits(self, ids(BASE) + frag(first="s2", last="s1"), "comes after last")

    def test_fragments_partially_overlapping_exit(self):
        t = ids(BASE + THIRD) + frag(first="s1", last="s2") + frag(first="s2", last="s3")
        exits(self, t, "fragments 1 and 2 overlap without nesting")

    def test_fragment_missing_first_exits(self):
        exits(self, ids(BASE) + frag().replace('first = "s1"\n', ""), "first is missing or not a string")

    def test_fragment_guard_not_a_string_exits(self):
        exits(self, ids(BASE) + frag().replace('guard = "until done"', "guard = 3"),
              "guard is missing or not a string")

    def test_fragment_evidence_without_status_still_resolves(self):
        exits(self, ids(BASE) + frag(evidence='"crates/nope/src/gone.rs"'),
              "evidence cites paths that do not resolve")

    def test_fragment_evidence_not_a_string_exits(self):
        exits(self, ids(BASE) + frag(evidence="5"), "evidence must be a str")

    def test_fragments_with_equal_ranges_exit(self):
        exits(self, ids(BASE) + frag() + frag(operator="opt"), "cover the same steps")

    def test_fragment_status_needs_marked_steps(self):
        exits(self, ids(BASE) + frag(status='"#736"', evidence='"#736"'), "needs the steps marked")

    def test_fragment_planned_status_needs_issue_in_evidence(self):
        exits(self, ids(LIVE) + frag(status='"#736"', evidence='"#999"'), "is not in its evidence")


class FragmentRendering(unittest.TestCase):
    def test_fragment_draws_operator_and_guard(self):
        svg = render(ids(BASE) + frag())
        self.assertIn(">loop<", svg)
        self.assertIn("[until done]", svg)

    def test_fragment_status_shows_stereotype(self):
        svg = render(ids(LIVE) + frag(operator="opt", status='"#736"', evidence='"#736"'))
        self.assertIn("«#736»", svg)

    def test_nested_fragments_sharing_a_first_step_stack_their_headers(self):
        svg = render(ids(BASE) + frag(first="s1", last="s2") + frag(operator="opt", first="s1", last="s1"))
        self.assertLess(text_y(svg, "loop<"), text_y(svg, "opt<"))
        r = frag_rects(svg)
        self.assertGreater(r[2][0], r[1][0])
        self.assertLess(r[2][0] + r[2][2], r[1][0] + r[1][2])

    def test_adjacent_fragments_do_not_overlap(self):
        svg = render(ids(BASE + THIRD) + frag(first="s1", last="s1") + frag(operator="opt", first="s2", last="s2"))
        r = frag_rects(svg)
        self.assertGreaterEqual(r[2][1], r[1][1] + r[1][3])
        self.assertLessEqual(r[2][1] + 14, text_y(svg, "2. second") - 10)

    def test_nested_fragments_sharing_a_last_step_nest_their_bottoms(self):
        svg = render(ids(BASE) + frag(first="s1", last="s2") + frag(operator="opt", first="s2", last="s2"))
        r = frag_rects(svg)
        self.assertLess(r[2][1] + r[2][3], r[1][1] + r[1][3])

    def test_fragment_on_last_step_ends_above_the_legend(self):
        svg = render(ids(LIVE) + frag())
        r = frag_rects(svg)
        self.assertLess(r[1][1] + r[1][3], text_y(svg, "«live» built"))

    def test_guard_fits_bare_but_not_with_its_stereotype_exits(self):
        g = "g" * 40
        self.assertIn(f"[{g}]", render(ids(LIVE) + frag(operator="opt", guard=g)))
        exits(self, ids(LIVE) + frag(operator="opt", guard=g, status='"#736"', evidence='"#736"'),
              "guard does not fit")

    def test_guard_wider_than_its_box_exits(self):
        exits(self, ids(BASE) + frag(guard="g" * 300), "guard does not fit")

    def test_statused_and_unstatused_fragments_render_together(self):
        t = ids(LIVE) + frag() + frag(operator="opt", first="s1", last="s1", status='"#736"', evidence='"#736"')
        self.assertIn("«#736»", render(t))

    def test_no_fragment_output_unchanged(self):
        self.assertNotIn("data-frag", render(BASE))

    def test_loop_is_shaded_and_opt_is_not(self):
        svg = render(ids(BASE) + frag(first="s1", last="s2") + frag(operator="opt", first="s1", last="s1"))
        self.assertEqual(svg.count("data-frag-fill"), 1)


if __name__ == "__main__":
    unittest.main()
