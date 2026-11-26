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


class MalformedInput(unittest.TestCase):
    def test_toml_syntax_error_exits_naming_the_file(self):
        exits(self, "precondition =\n" + BASE, "is not valid TOML")

    def test_step_without_label_exits(self):
        exits(self, BASE.replace('label = "first"\n', ""), "step 1: label must be a str")

    def test_call_to_unknown_participant_exits(self):
        exits(self, BASE.replace('to = "b"', 'to = "zz"', 1), "spans unknown participant 'zz'")

    def test_control_character_exits(self):
        exits(self, 'precondition = "\\u0001"\n' + BASE, "a character XML cannot carry")


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

    def test_step_after_a_fragment_clears_its_bottom(self):
        svg = render(ids(BASE + THIRD) + frag(first="s1", last="s1"))
        r = frag_rects(svg)[1]
        self.assertGreaterEqual(text_y(svg, "2. second") - 12, r[1] + r[3])

    def test_nested_fragments_sharing_a_last_step_nest_their_bottoms(self):
        svg = render(ids(BASE) + frag(first="s1", last="s2") + frag(operator="opt", first="s2", last="s2"))
        r = frag_rects(svg)
        self.assertLess(r[2][1] + r[2][3], r[1][1] + r[1][3])

    def test_fragment_on_last_step_ends_above_the_legend(self):
        svg = render(ids(LIVE) + frag())
        r = frag_rects(svg)
        self.assertLess(r[1][1] + r[1][3], text_y(svg, "«live» built"))

    def test_guard_fits_bare_but_not_with_its_stereotype_exits(self):
        g = "g" * 46
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

    def test_fragment_widens_to_enclose_its_steps_text(self):
        ev = "e" * 70
        svg = render(ids(BASE.replace('evidence = "crates/maknae-kernel/src/task.rs"', f'evidence = "{ev}"', 1))
                     + frag())
        x = float(re.search(r'<text x="([-\d.]+)"[^>]*>' + ev + "<", svg).group(1))
        r = frag_rects(svg)[1]
        self.assertLessEqual(r[0], x - len(ev) * 4.6 / 2)
        self.assertGreaterEqual(r[0] + r[2], x + len(ev) * 4.6 / 2)

    def test_step_text_that_cannot_fit_its_box_exits(self):
        t = ids(BASE.replace('evidence = "crates/maknae-kernel/src/task.rs"', f'evidence = "{"e" * 75}"', 1))
        exits(self, t + frag() + frag(operator="opt", first="s1", last="s1"), "text runs past the box")

    def test_box_encloses_the_step_number_prefix(self):
        label = "w" * 60
        svg = render(ids(BASE.replace('label = "first"', f'label = "{label}"')) + frag(first="s1", last="s1"))
        x = float(re.search(r'<text x="([-\d.]+)"[^>]*>1\. ' + label + "<", svg).group(1))
        r = frag_rects(svg)[1]
        half = len("1. " + label) * 5.6 / 2
        self.assertLessEqual(r[0], x - half)
        self.assertGreaterEqual(r[0] + r[2], x + half)

    def test_box_encloses_the_open_decision_tag(self):
        t = ids(BASE).replace('label = "first"\nkind = "call"\nfrom = "a"\nto = "b"\n'
                              'evidence = "crates/maknae-kernel/src/task.rs"',
                              'label = "first"\nkind = "self"\nfrom = "a"\nto = "a"\n'
                              'evidence = "short"\ndecide = ["question?"]')
        svg = render(t + frag(last="s1", first="s1"))
        x = float(re.search(r'<text x="([-\d.]+)"[^>]*>open decision D1<', svg).group(1))
        r = frag_rects(svg)[1]
        self.assertGreaterEqual(r[0] + r[2], x + len("open decision D1") * 4.8)

    def test_loop_fill_is_drawn_behind_the_trust_boundary(self):
        bound = '\n[[boundary]]\nbefore = "b"\nleft = ""\nright = "trusted"\n'
        svg = render(ids(BASE).replace("[[participant]]", bound + "\n[[participant]]", 1) + frag())
        self.assertLess(svg.index("data-frag-fill"), svg.index('stroke-dasharray="7 4"'))

    def test_loop_is_shaded_and_opt_is_not(self):
        svg = render(ids(BASE) + frag(first="s1", last="s2") + frag(operator="opt", first="s1", last="s1"))
        self.assertEqual(svg.count("data-frag-fill"), 1)


THREE = BASE.replace("[[step]]", '''[[participant]]
id = "c"
label = "C"
stereo = "«c»"
kind = "external"

[[step]]''', 1)


def ref_step(frm="b", to="c", **extra) -> str:
    rows = ['id = "r"', 'label = "a tool call"', 'kind = "ref"', f'from = "{frm}"', f'to = "{to}"',
            'target = "generated-tool-invocation.svg"', 'evidence = "crates/maknae-kernel/src/task.rs"']
    rows += [f"{k} = {v}" for k, v in extra.items()]
    return "\n".join(rows) + "\n"


def with_ref(toml_text: str, step: str) -> str:
    """Put the ref step first, ahead of the file's own steps."""
    head, _, rest = toml_text.partition("[[step]]\n")
    return head + "[[step]]\n" + step + "\n[[step]]\n" + rest


def ref_rect(svg: str) -> tuple:
    m = re.search(r'<rect data-ref="\d+" x="([-\d.]+)" y="([-\d.]+)" width="([-\d.]+)" '
                  r'height="([-\d.]+)"', svg)
    return tuple(float(v) for v in m.groups())


class RefSteps(unittest.TestCase):
    def test_ref_needs_target(self):
        exits(self, with_ref(ids(THREE), ref_step().replace('target = "generated-tool-invocation.svg"\n', "")),
              "ref step has no target")

    def test_ref_unknown_target_exits(self):
        exits(self, with_ref(ids(THREE), ref_step().replace("generated-tool-invocation.svg", "nope.svg")),
              "ref target 'nope.svg' is not a generated product")

    def test_ref_target_not_a_string_exits(self):
        exits(self, with_ref(ids(THREE), ref_step().replace('"generated-tool-invocation.svg"', "5")),
              "target must be a str")

    def test_ref_takes_no_decide(self):
        exits(self, with_ref(ids(THREE), ref_step(decide='["x"]')), "a ref step takes no decide")

    def test_ref_from_or_to_unknown_exits(self):
        exits(self, with_ref(ids(THREE), ref_step(frm="zz")), "spans unknown participant 'zz'")

    def test_ref_draws_tag_label_and_target(self):
        svg = render(with_ref(ids(THREE), ref_step()))
        self.assertIn(">ref<", svg)
        self.assertIn("a tool call", svg)
        self.assertIn(">generated-tool-invocation.svg<", svg)
        self.assertEqual(svg.count("marker-end"), 2)

    def test_ref_from_right_of_to_draws_left_to_right(self):
        svg = render(with_ref(ids(THREE), ref_step(frm="b", to="a")))
        self.assertLess(ref_rect(svg)[0], 92)

    def test_fragment_may_start_on_a_ref_step(self):
        svg = render(with_ref(ids(THREE), ref_step()) + frag(first="r", last="s1"))
        f, r = frag_rects(svg)[1], ref_rect(svg)
        self.assertLessEqual(f[0], r[0])
        self.assertGreaterEqual(f[0] + f[2], r[0] + r[2])
        self.assertLessEqual(f[1] + 14, r[1])

    def test_fragment_encloses_a_ref_on_lifeline_zero(self):
        svg = render(with_ref(ids(THREE), ref_step(frm="a")) + frag(first="r", last="s1"))
        f, r = frag_rects(svg)[1], ref_rect(svg)
        self.assertLessEqual(f[0], r[0])
        self.assertGreaterEqual(f[0] + f[2], r[0] + r[2])

    def test_ref_text_wider_than_its_box_exits(self):
        exits(self, with_ref(ids(THREE), ref_step().replace("a tool call", "w" * 120)),
              "text does not fit its box")

    def test_product_names_match_main(self):
        self.assertIn("generated-task-tool-lifecycle.svg", generate.PRODUCT_NAMES)

    def test_tool_credentials_is_a_product(self):
        self.assertIn("generated-tool-credentials.svg", generate.PRODUCT_NAMES)
        self.assertTrue(generate.sequence("tool-credentials.toml").startswith("<svg"))


if __name__ == "__main__":
    unittest.main()
