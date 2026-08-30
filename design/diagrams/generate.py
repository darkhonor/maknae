#!/usr/bin/env python3
"""Generate the derived architecture diagrams for `design/diagrams/` (issue #196).

Emits SVG directly. No Mermaid, no Graphviz, no npm, no `xtask` — Python 3 and
nothing else, matching this repo's existing tooling idiom (`ci/gates/*.py`).

WHAT THIS DERIVES, AND FROM WHAT. Every fact rendered comes from something that
ENFORCES it, never from something that merely describes it:

  TCB membership   ci/gates/lib.sh   — the list P1 actually polices
  binary linkage   rust-audit-info   — the real transitive closure in the artifact
  members/bins     cargo metadata    — the workspace itself

`packaging/isolation-contract.md` is deliberately NOT a source: it mirrors
lib.sh, and a diagram generated from a mirror can agree with the mirror while
both drift from the gate.

NOTATION. UML 2.5.1 (OMG formal/2017-12-05). Where Maknae needs something UML
does not model — "this edge is refused by a CI gate" — it is expressed as a UML
STEREOTYPE («gate:P1»), which is UML's own extension mechanism, rather than as a
private colour or glyph. Colour is styling only and carries no meaning; a reader
who knows UML needs no key from us.
"""

import hashlib
import json
import tomllib
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "design" / "diagrams"

# Externals worth a box. Cargo.lock holds ~260 crates; rendering them is a
# hairball. Curated for SECURITY or ARCHITECTURAL weight, not usage count —
# edit this list, not the logic below.
KEY_EXTERNALS = {
    "tokio": "async runtime",
    "rustls": "TLS 1.3",
    "tokio-rustls": "TLS over the UDS",
    "aws-lc-fips-sys": "FIPS 140-3 module",
    "aws-lc-rs": "FIPS provider",
    "rustix": "safe SCM_RIGHTS (zero-unsafe)",
    "nix": "syscall surface",
    "zeroize": "secret hygiene",
    "vaultrs": "Vault client",
    "rcgen": "plane identity CSR",
    "yaml-rust2": "config parser (untrusted input)",
}

# --- house styling. NOT notation: UML specifies shape/line/arrowhead, not palette.
FONT = "Helvetica, Arial, sans-serif"
INK, MUTED = "#2C2C2A", "#5F5E5A"
TRUST_FILL, TRUST_INK, TRUST_LINE = "#EEEDFE", "#26215C", "#534AB7"
PLAIN_FILL, PLAIN_LINE = "#F1EFE8", "#5F5E5A"
OK_FILL, OK_LINE = "#E1F5EE", "#0F6E56"
WARN = "#B3452F"


def sh(*args: str) -> str:
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=True).stdout


def gate_facts() -> dict:
    """PRIVILEGED_CRATES / UNTRUSTED_BIN / TRUST_CONSUMER_ALLOW, parsed from the gate."""
    src = (ROOT / "ci" / "gates" / "lib.sh").read_text()
    priv = re.search(r"PRIVILEGED_CRATES=\(([^)]*)\)", src).group(1).split()
    untrusted = re.search(r'UNTRUSTED_BIN="([^"]+)"', src).group(1)
    allow = re.findall(r'"([a-z0-9-]+)=([a-z0-9-]+)"', src)
    return {"privileged": sorted(priv), "untrusted_bin": untrusted, "allow": sorted(allow)}


def workspace() -> dict:
    meta = json.loads(sh("cargo", "metadata", "--no-deps", "--format-version", "1"))
    members, bins = [], []
    for p in meta["packages"]:
        if any(t["kind"] == ["bin"] for t in p["targets"]):
            bins.append(p["name"])
        if any(t["kind"] in (["lib"], ["rlib"]) for t in p["targets"]):
            members.append(p["name"])
    return {"crates": sorted(members), "bins": sorted(bins)}


def linkage(binaries: list[str]) -> dict:
    """The REAL closure per artifact, from the cargo-auditable inventory."""
    out = {}
    for b in binaries:
        art = ROOT / "target" / "release" / b
        if not art.exists():
            sys.exit(f"missing {art} — run:  cargo auditable build -p {b} --release")
        inv = json.loads(sh("rust-audit-info", str(art)))
        out[b] = sorted({p["name"] for p in inv.get("packages", [])})
    return out


def provenance() -> str:
    """The state of the INPUTS these diagrams were derived from.

    Deliberately NOT `HEAD`. A HEAD-based stamp can never be correct for a
    committed diagram: the commit that *carries* an SVG is necessarily one later
    than the commit whose sources produced it, so the stamp chases itself and
    "regenerate, then diff" can never come back clean. That is not a cosmetic
    problem — it makes the artifact unverifiable, which is the one thing the
    stamp exists to prevent. (Found by review on #202, after a first version
    stamped HEAD and shipped a stale, dirty-worktree hash.)

    So the stamp names the last commit that touched an actual INPUT — `lib.sh`
    and the manifests. Unrelated commits do not move it, regeneration is
    idempotent, and a reviewer can check the claim by regenerating and getting
    byte-identical files back.
    """
    inputs = ["ci/gates/lib.sh", "Cargo.toml"] + sorted(
        str(p.relative_to(ROOT)) for p in ROOT.glob("*/*/Cargo.toml")
    )
    sha = sh("git", "log", "-1", "--format=%h", "--", *inputs).strip() or "unknown"
    date = sh("git", "log", "-1", "--format=%cs", "--", *inputs).strip() or "unknown"
    dirty = ""
    if sh("git", "status", "--porcelain", "--", *inputs).strip():
        # Loud on purpose: an input was edited but not committed, so these
        # diagrams came from a state that exists nowhere in history.
        dirty = " +UNCOMMITTED-INPUTS"
    return f"inputs at {sha}{dirty} · {date}"


def content_stamp(rel: str) -> str:
    """Provenance for a CURATED input, as a hash of its bytes.

    A commit sha cannot work here. `standards-profile.toml` and the SVG it
    produces necessarily travel in the SAME commit, so a sha computed at
    generation time is always the PREVIOUS commit's -- the identical chasing
    failure that made the first HEAD-based stamp unverifiable (#202). Review of
    #204 then found the mirror-image bug: excluding the curated file entirely
    let a claim change -- a status flipping `adopted` to `enforced` -- regenerate
    the diagram under an UNCHANGED stamp.

    A content hash escapes both. It is knowable before the commit exists, so
    regeneration stays idempotent; it moves whenever any claim moves; and a
    reviewer checks it with `sha256sum`, needing no git history at all.

    The generator itself is deliberately NOT hashed. Its effect is already
    carried by the SVG bytes -- a renderer change that alters output changes the
    file, and one that does not is not a fact about the artifact. Hashing it
    would rewrite every footer on every unrelated generator edit.
    """
    h = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()[:10]
    return f"{rel}@{h}"


# --- evidence resolution --------------------------------------------------

_ADR = re.compile(r"\bADR-(\d{4})\b")
_PATH = re.compile(r"[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)+|\b[A-Za-z0-9_\-]+\.(?:toml|md)\b")


def check_evidence(rows: list, field: str, where: str) -> None:
    """Every evidence citation must name something a reader can open.

    Hard-fails generation. The rule was stated in the README from the start and
    enforced only by an ad-hoc script whose regex required a file EXTENSION --
    so `design/references/oauth-compliance` (real file: `.md`) was never a
    candidate to check, and shipped dead. Found by review on #204. An
    unenforced rule is a wish, so this now runs on every generation.
    """
    bad = []
    for r in rows:
        ev = r.get(field, "")
        for adr in _ADR.findall(ev):
            if not list(ROOT.glob(f"design/adr/ADR-{adr}-*.md")):
                bad.append((r, f"ADR-{adr}"))
        for tok in _PATH.findall(ev):
            tok = tok.split(":")[0].rstrip(".,;")
            # A slash alone does not make a path: "TLS 1.2/1.3", "SC-10/AC-12"
            # and RFC lists all contain one. A repo path starts at a directory
            # that actually exists at the root, which none of those do.
            head = tok.split("/")[0]
            if "/" in tok and not (ROOT / head).is_dir():
                continue
            if (ROOT / tok).exists():
                continue
            near = sorted(p.name for p in ROOT.glob(tok + ".*"))
            bad.append((r, tok + (f"  (did you mean {near[0]}?)" if near else "")))
    if bad:
        lines = "\n".join(f"    {r.get('name', r.get('label', '?'))}: {t}" for r, t in bad)
        sys.exit(f"{where}: evidence cites paths that do not resolve:\n{lines}")


# --- facts: the internal crate graph and each crate's direct externals -----

def crate_graph() -> dict:
    """Direct, normal-kind dependencies among workspace members, plus each
    member's direct externals. dev- and build-dependencies are excluded: they
    are not in any shipped artifact, so they are not part of what this diagram
    claims."""
    meta = json.loads(sh("cargo", "metadata", "--format-version", "1"))
    members = {p["name"] for p in meta["packages"] if p["id"] in meta["workspace_members"]}
    internal, external = {}, {}
    for p in meta["packages"]:
        if p["name"] not in members:
            continue
        ins, exs = set(), set()
        for d in p["dependencies"]:
            if d["kind"] not in (None, "null"):
                continue
            (ins if d["name"] in members else exs).add(d["name"])
        internal[p["name"]] = sorted(ins)
        external[p["name"]] = sorted(exs)
    return {"members": sorted(members), "deps": internal, "ext": external}


def layer_of(deps: dict) -> dict:
    """Longest-path layering. The graph is a DAG (cargo enforces it), so the
    recursion terminates; the `seen` guard is belt-and-braces, not a cycle
    handler."""
    lvl = {}

    def L(n, seen=()):
        if n in lvl:
            return lvl[n]
        if n in seen:
            return 0
        lvl[n] = 1 + max([L(d, seen + (n,)) for d in deps.get(n, [])], default=-1)
        return lvl[n]

    for n in deps:
        L(n)
    return lvl


def order_rows(rows: dict, deps: dict, sweeps: int = 12) -> dict:
    """Barycentre ordering, swept both ways, to cut edge crossings.

    Without it the bands are alphabetical and the kernel's twelve edges cross
    nearly everything. This is the standard Sugiyama heuristic, not an exact
    minimum -- it does not need to be, it needs to be readable."""
    pos = {n: i for r in rows.values() for i, n in enumerate(r)}
    up = {n: [d for d in deps.get(n, [])] for n in pos}
    down = {}
    for n, ds in up.items():
        for d in ds:
            down.setdefault(d, []).append(n)
    for s in range(sweeps):
        use = up if s % 2 == 0 else down
        for lv in (sorted(rows) if s % 2 == 0 else sorted(rows, reverse=True)):
            r = rows[lv]
            key = {}
            for n in r:
                nb = [pos[x] for x in use.get(n, []) if x in pos]
                key[n] = sum(nb) / len(nb) if nb else pos[n]
            rows[lv] = sorted(r, key=lambda n: (key[n], n))
            for i, n in enumerate(rows[lv]):
                pos[n] = i
    return rows




# --- SVG primitives -------------------------------------------------------

def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def text(x, y, s, size=12, weight="400", fill=INK, anchor="start", mono=False,
         halo=None):
    fam = "ui-monospace, SFMono-Regular, Menlo, monospace" if mono else FONT
    h = (f' stroke="{halo}" stroke-width="3.5" paint-order="stroke" '
         'stroke-linejoin="round"') if halo else ""
    return (f'<text x="{x}" y="{y}" text-anchor="{anchor}" font-family="{fam}" '
            f'font-size="{size}" font-weight="{weight}" fill="{fill}"{h}>{esc(s)}</text>')


def box(x, y, w, h, fill, stroke, rx=8, dash=None, sw="0.75"):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" '
            f'stroke="{stroke}" stroke-width="{sw}"{d}/>')


def svg(w, h, body, title, desc):
    return (f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'xmlns="http://www.w3.org/2000/svg" role="img">\n'
            f'  <title>{esc(title)}</title>\n  <desc>{esc(desc)}</desc>\n'
            f'  <rect x="0" y="0" width="{w}" height="{h}" fill="#FFFFFF"/>\n'
            + body + "\n</svg>\n")


def footer(w, h, note):
    return (text(24, h - 16, note, 10, fill=MUTED)
            + text(w - 24, h - 16, "UML 2.5.1 (OMG formal/2017-12-05)", 10,
                   fill=MUTED, anchor="end"))


# --- D2: crate x binary linkage matrix ------------------------------------

def d2_matrix(gates, ws, links, prov) -> str:
    """What each shipped artifact ACTUALLY links, and which cells a gate refuses.

    A matrix, not a graph — no layout engine needed. Shaped after DoDAF SV-6's
    resource-flow matrix; the cells carry UML stereotypes.
    """
    bins = ws["bins"]
    # rows: workspace library crates that ANY binary links, plus the key externals
    linked = sorted({c for b in bins for c in links[b]} & set(ws["crates"]))
    ext = sorted({c for b in bins for c in links[b]} & set(KEY_EXTERNALS))

    # P1's allowlist is PER CONSUMER — "maknaed=maknae-kernel",
    # "maknae-spifc=maknae-spif-compile". Any other binary/privileged-crate pair
    # is refused, not merely absent: maknaed pulling the SPIF compiler fails P1
    # exactly as the untrusted client pulling the kernel does. An earlier version
    # marked only the untrusted binary and so under-reported what the gate does.
    allowed = {b: {c for (bb, c) in gates["allow"] if bb == b} for b in bins}
    rowh, x0, colw = 22, 250, 124
    top = 152
    h = top + (len(linked) + len(ext) + 3) * rowh + 96
    w = x0 + colw * len(bins) + 40

    p = [box(24, 24, w - 48, h - 64, "#FFFFFF", MUTED, rx=16),
         text(44, 52, "Crate × binary linkage, and what the gates refuse", 15, "600"),
         text(44, 72, "Derived from the cargo-auditable inventory of each built artifact — the real "
                      "transitive closure, not declared dependencies.", 11, fill=MUTED),
         text(44, 88, "«» denotes a UML stereotype. A refused cell is refused by gate P1's "
                      "per-consumer allowlist, not merely absent today.", 11, fill=MUTED)]

    # column heads
    for i, b in enumerate(bins):
        cx = x0 + i * colw + colw / 2
        untrusted = b == gates["untrusted_bin"]
        p.append(box(x0 + i * colw + 6, top - 44, colw - 12, 34,
                     PLAIN_FILL if untrusted else TRUST_FILL,
                     PLAIN_LINE if untrusted else TRUST_LINE,
                     dash="4 3" if untrusted else None))
        p.append(text(cx, top - 29, b, 12, "600", anchor="middle",
                      fill=INK if untrusted else TRUST_INK, mono=True))
        p.append(text(cx, top - 16, "«untrusted»" if untrusted else "«trusted»",
                      9, anchor="middle", fill=MUTED if untrusted else TRUST_LINE))

    def rows(items, label, y):
        p.append(text(44, y - 6, label, 11, "600", fill=MUTED))
        for j, c in enumerate(items):
            ry = y + j * rowh
            priv = c in gates["privileged"]
            if j % 2 == 0:
                p.append(box(40, ry, w - 80, rowh, "#FAFAF8", "none", rx=3, sw="0"))
            p.append(text(48, ry + 14, c, 11, "600" if priv else "400",
                          fill=TRUST_INK if priv else INK, mono=True))
            if priv:
                p.append(text(48 + 8.2 * len(c) + 8, ry + 14, "«privileged»", 9,
                              fill=TRUST_LINE))
            for i, b in enumerate(bins):
                cx = x0 + i * colw + colw / 2
                if c in links[b]:
                    p.append(text(cx, ry + 15, "●", 13, anchor="middle",
                                  fill=TRUST_LINE if priv else OK_LINE))
                elif priv and c not in allowed.get(b, set()):
                    # Not merely absent: P1 refuses it, and P2 proves the artifact agrees.
                    # Beside the mark, not beneath it: at 8pt below a 22px row the
                    # label printed over the next crate's name.
                    p.append(text(cx - 6, ry + 15, "✕", 12, anchor="middle", fill=WARN))
                    p.append(text(cx + 4, ry + 15, "«gate:P1»", 8, fill=WARN))
                else:
                    p.append(text(cx, ry + 15, "·", 12, anchor="middle", fill="#C9C7C0"))
        return y + len(items) * rowh

    y = rows(linked, "workspace crates", top)
    y = rows(ext, "key external dependencies", y + 30)

    # legend
    ly = y + 26
    p.append(text(44, ly, "● linked", 10, fill=OK_LINE))
    p.append(text(130, ly, "● linked (privileged)", 10, fill=TRUST_LINE))
    p.append(text(285, ly, "✕ refused by gate", 10, fill=WARN))
    p.append(text(410, ly, "· not linked", 10, fill=MUTED))
    p.append(footer(w, h, f"generated from ci/gates/lib.sh + rust-audit-info · {prov}"))
    return svg(w, h, "\n  ".join(p),
               "Maknae crate to binary linkage matrix",
               "Which workspace crates and key external dependencies each Maknae binary "
               "links, with the cells a CI gate refuses marked as UML stereotypes.")


# --- D1: TCB boundary, UML component diagram ------------------------------

def d1_tcb(gates, ws, links, prov) -> str:
    """What is in the TCB and where the boundary runs.

    UML 2.5.1 component diagram: components in packages, «stereotypes» for the
    trust classification. The boundary is a package, not a colour — colour here
    is styling and carries nothing a reader must decode.
    """
    daemon = "maknaed"
    client = gates["untrusted_bin"]
    priv = set(gates["privileged"])

    d_crates = sorted(set(links[daemon]) & set(ws["crates"]))
    c_crates = sorted(set(links[client]) & set(ws["crates"]))
    shared = sorted(set(d_crates) & set(c_crates))
    tcb = sorted(c for c in d_crates if c in priv)
    daemon_only = sorted(c for c in d_crates if c not in priv and c not in shared)

    colw, cellh, per = 176, 26, 3
    w = 900

    def block(title, stereo, items, x, y, fill, line, ink, dash=None, caption=None):
        """One UML package. Height is COMPUTED from its contents and caption —
        an earlier version used a fixed formula and the caption overprinted the
        bottom border on every block that had one."""
        rows = (len(items) + per - 1) // per
        bh = 40 + rows * cellh + (20 if caption else 6)
        out = [box(x, y, colw * per + 24, bh, fill, line, rx=16, dash=dash),
               text(x + 16, y + 24, title, 13, "600", fill=ink),
               text(x + 16 + 7.6 * len(title) + 10, y + 24, stereo, 10, fill=line)]
        for k, c in enumerate(items):
            cx, cy = x + 14 + (k % per) * colw, y + 36 + (k // per) * cellh
            out.append(box(cx, cy, colw - 12, cellh - 7, "#FFFFFF", line, rx=6))
            out.append(text(cx + 9, cy + 13, c, 10, "500", fill=ink, mono=True))
        if caption:
            out.append(text(x + 16, y + bh - 11, caption, 10,
                            fill=WARN if dash else line))
        return out, bh

    p = [text(40, 44, "Trusted computing base — component view", 16, "600"),
         text(40, 64, "Membership derived from ci/gates/lib.sh, the list the P1 gate polices. "
                      "Linkage from the built artifacts.", 11, fill=MUTED)]

    y = 86
    b, bh = block("Trust plane · maknaed", "«trusted»", tcb, 40, y,
                  TRUST_FILL, TRUST_LINE, TRUST_INK,
                  caption="the TCB — privileged crates, forbidden to the client binary")
    p += b
    y += bh + 20

    b, bh = block("Trust plane · supporting", "«component»", daemon_only, 40, y,
                  OK_FILL, OK_LINE, "#04342C",
                  caption="linked by the daemon only — not privileged, so not in the TCB")
    p += b
    y += bh + 20

    b, bh = block("Shared, non-privileged", "«component»", shared, 40, y,
                  "#FFFFFF", MUTED, INK,
                  caption="linked by BOTH planes — in the TCB of neither; the client needs "
                          "these to connect and to delegate descriptors")
    p += b
    y += bh + 20

    b, bh = block(f"Untrusted plane · {client}", "«untrusted»", [], 40, y,
                  PLAIN_FILL, PLAIN_LINE, INK, dash="5 4",
                  caption="links NO privileged crate — refused by «gate:P1» in the manifests, "
                          "witnessed in the built artifact by «gate:P2»")
    p += b
    y += bh

    h = y + 60
    p.append(footer(w, h, f"generated from ci/gates/lib.sh + rust-audit-info · {prov}"))
    return svg(w, h, "\n  ".join(p),
               "Maknae trusted computing base",
               "UML component view of Maknae's TCB: privileged crates inside the trust "
               "plane, the untrusted client binary, and the non-privileged crates both link.")


# --- D-StdV1: DoDAF 2.02 Standards Profile ---------------------------------

STATUS_STYLE = {
    "enforced": (OK_LINE, "enforced", "implemented, and CI or the runtime refuses a violation"),
    "adopted": (TRUST_LINE, "adopted", "implemented and relied upon; not mechanically checked"),
    "emerging": ("#8A6D1F", "emerging", "applies to a surface not yet built"),
    "excluded": (MUTED, "excluded", "deliberately out of scope, decision recorded"),
}
STATUS_ORDER = ["enforced", "adopted", "emerging", "excluded"]


def stdv1(prov: str) -> str:
    """DoDAF 2.02 StdV-1 — the standards this system claims, and what enforces each.

    A tabular product by nature; StdV-1 is a profile, not a picture. The
    `status` split is the point: DoDAF separates mandated/current from emerging,
    and a profile that blurs them is a wish list. The `evidence` column is the
    part most StdV-1s lack — every row names a file, gate or ADR a reader can open.
    """
    rows = tomllib.load((OUT / "standards-profile.toml").open("rb"))["standard"]
    check_evidence(rows, "evidence", "standards-profile.toml")
    rows.sort(key=lambda r: (STATUS_ORDER.index(r["status"]), r["name"].lower()))

    w, lh = 1220, 19
    x = {"name": 44, "ver": 296, "cat": 500, "app": 660, "ev": 660}
    # +112: the status-group headings and the closing note both sit below the
    # last row. An earlier version sized only for rows and clipped the note.
    h = 150 + sum(2 * lh + 10 for _ in rows) + 16 * len(STATUS_ORDER) + 112

    def fit(sv: str, avail_px: float, size: float) -> str:
        """Truncate to the column. A value that overruns prints over its
        neighbour, which is worse than losing its tail."""
        n = int(avail_px / (size * 0.56))
        return sv if len(sv) <= n else sv[: n - 1].rstrip() + "\u2026"

    p = [text(40, 46, "Standards profile — DoDAF StdV-1", 17, "600"),
         text(40, 68, "The technical standards Maknae claims, the elements they apply to, and what "
                      "enforces each. Status separates what is mechanically", 11, fill=MUTED),
         text(40, 83, "checked from what is merely implemented — a profile that blurs the two is a "
                      "wish list.", 11, fill=MUTED)]

    hy = 112
    for label, cx in [("Standard", x["name"]), ("Version / profile", x["ver"]),
                      ("Category", x["cat"]), ("Applies to  ·  Evidence", x["app"])]:
        p.append(text(cx, hy, label, 10, "600", fill=MUTED))
    p.append(f'<line x1="40" y1="{hy + 8}" x2="{w - 40}" y2="{hy + 8}" '
             f'stroke="{MUTED}" stroke-width="0.75"/>')

    y = hy + 26
    seen = set()
    for r in rows:
        colour, badge, _ = STATUS_STYLE[r["status"]]
        if r["status"] not in seen:
            seen.add(r["status"])
            p.append(text(44, y + 2, STATUS_STYLE[r["status"]][2], 9, "600", fill=colour))
            y += 16
        p.append(box(40, y - 12, w - 80, 2 * lh + 6, "#FCFCFB", "none", rx=4, sw="0"))
        p.append(text(x["name"], y + 2, fit(r["name"], x["ver"] - x["name"] - 12, 11), 11, "600"))
        p.append(box(x["name"] - 4, y + 8, 62, 13, "#FFFFFF", colour, rx=6))
        p.append(text(x["name"] + 27, y + 18, badge, 8, "600", fill=colour, anchor="middle"))
        p.append(text(x["ver"], y + 2, fit(r["version"], x["cat"] - x["ver"] - 12, 10), 10,
                      fill=INK, mono=True))
        p.append(text(x["cat"], y + 2, fit(r["category"], x["app"] - x["cat"] - 12, 10), 10, fill=MUTED))
        p.append(text(x["app"], y + 2, fit(r["applies_to"], w - x["app"] - 44, 10), 10, fill=INK))
        p.append(text(x["ev"], y + 17, fit(r["evidence"], w - x["ev"] - 44, 9), 9,
                      fill=MUTED, mono=True))
        y += 2 * lh + 10

    p.append(text(40, y + 26, "Every row names evidence a reader can open. A claim with no evidence "
                              "does not belong in this profile.", 10, fill=MUTED))
    p.append(text(40, h - 26, f"source: {content_stamp('design/diagrams/standards-profile.toml')}",
                  10, fill=MUTED))
    p.append(text(w - 40, h - 26, "DoDAF 2.02 Change 1 · StdV-1", 10, fill=MUTED, anchor="end"))
    return svg(w, h, "\n  ".join(p),
               "Maknae standards profile (DoDAF StdV-1)",
               "The technical standards Maknae conforms to, the elements each applies to, "
               "whether the claim is mechanically enforced, and the evidence for it.")


# --- D4: workspace packages, UML 2.5.1 package diagram --------------------

def d4_packages(gates, cg, prov) -> str:
    """How the crates fit together and what they pull in.

    UML 2.5.1 package diagram: folder-shaped packages, «stereotype» for the
    trust classification, dependencies as dashed lines with an open arrowhead
    pointing at the SUPPLIER (the thing depended upon), per UML 7.8.4.
    """
    deps, ext = cg["deps"], cg["ext"]
    priv = set(gates["privileged"])
    bins = {"maknaed", gates["untrusted_bin"]}
    lvl = layer_of(deps)
    rows = {}
    for n, l in lvl.items():
        rows.setdefault(l, []).append(n)
    for l in rows:
        rows[l].sort()
    rows = order_rows(rows, deps)

    BW, GAP, PAD, TOP, PERROW, GUT = 150, 18, 44, 112, 8, 84
    widest = min(PERROW, max(len(r) for r in rows.values()))
    W = PAD * 2 + GUT + widest * BW + (widest - 1) * GAP

    def wrap(items, cols=27):
        out, cur = [], ""
        for it in items:
            add = it if not cur else cur + ", " + it
            if len(add) > cols and cur:
                out.append(cur + ",")
                cur = it
            else:
                cur = add
        if cur:
            out.append(cur)
        return out

    # geometry first: every box's height depends on its external list
    geo, y, bands = {}, TOP, []
    for l in sorted(rows, reverse=True):
        band = rows[l]
        ytop = y
        for s0 in range(0, len(band), PERROW):
            sub = band[s0:s0 + PERROW]
            span = len(sub) * BW + (len(sub) - 1) * GAP
            hmax = 0
            for i, c in enumerate(sub):
                x0 = GUT + (W - GUT - span) / 2
                lines = wrap(ext.get(c, []))
                stereo = 11 if (c in priv or c in bins) else 0
                h = 37 + stereo + (len(lines) * 11 + 6 if lines else 0)
                geo[c] = {"x": x0 + i * (BW + GAP), "y": y, "h": h,
                          "lines": lines, "st": stereo}
                hmax = max(hmax, h)
            y += hmax + 44
        bands.append((l, ytop, y - 44))
    H = y + 74

    # layer bands, behind everything. The band is what makes a WRAPPED layer
    # legible: layer 0 spills onto a second row, and without the band that row
    # reads as a deeper layer when those packages are in fact leaves.
    p = []
    for l, ytop, ybot in bands:
        shade = "#FBFAF7" if l % 2 == 0 else "#FFFFFF"
        p.append(f'<rect x="0" y="{ytop-14:.0f}" width="{W}" '
                 f'height="{ybot-ytop+28:.0f}" fill="{shade}"/>')
        p.append(text(24, ytop + 4, f"layer {l}", 10, "600", fill=MUTED))
        if l == 0:
            p.append(text(24, ytop + 17, "no deps", 9, fill=MUTED))
    p += ['<defs><marker id="dep" viewBox="0 0 10 10" refX="9" refY="5" '
         'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
         f'<path d="M 0 1 L 9 5 L 0 9" fill="none" stroke="{MUTED}" '
         'stroke-width="1.2"/></marker></defs>']

    # edges BEHIND the packages: a supplier several layers down would otherwise
    # have its line clipped by whatever sits between, and the crossing matters
    # less than the box being readable.
    for c, ds in deps.items():
        for d in ds:
            if d not in geo:
                continue
            a, b = geo[c], geo[d]
            x1, y1 = a["x"] + BW / 2, a["y"] + a["h"]
            x2, y2 = b["x"] + BW / 2, b["y"]
            my = (y1 + y2) / 2
            hot = c in priv or c in bins
            p.append(f'<path d="M {x1:.0f} {y1:.0f} C {x1:.0f} {my:.0f} '
                     f'{x2:.0f} {my:.0f} {x2:.0f} {y2:.0f}" fill="none" '
                     f'stroke="{TRUST_LINE if hot else MUTED}" stroke-width="0.8" '
                     f'stroke-dasharray="4 3" opacity="{0.55 if hot else 0.3}" '
                     'marker-end="url(#dep)"/>')

    for c, g in geo.items():
        trusted, is_bin = c in priv, c in bins
        fill, line, ink = PLAIN_FILL, PLAIN_LINE, INK
        if trusted:
            fill, line, ink = TRUST_FILL, TRUST_LINE, TRUST_INK
        elif is_bin:
            fill, line, ink = OK_FILL, OK_LINE, "#04342C"
        x, yy, h = g["x"], g["y"], g["h"]
        # UML package: the tab, then the body.
        p.append(f'<path d="M {x} {yy+9} h 46 l 5 -9 h 0 v 9" fill="{fill}" '
                 f'stroke="{line}" stroke-width="0.75"/>')
        p.append(box(x, yy + 9, BW, h - 9, fill, line, rx=3))
        short = c.replace("maknae-", "") if c != "maknae" else "maknae"
        p.append(text(x + 9, yy + 26, short, 11, "600", fill=ink, mono=True))
        st = "«trusted»" if trusted else ("«artifact»" if is_bin else "")
        if st:
            p.append(text(x + 9, yy + 36, st, 8.5, fill=line))
        for k, ln in enumerate(g["lines"]):
            p.append(text(x + 9, yy + 37 + g["st"] + k * 11, ln, 8,
                          fill=MUTED, mono=True))

    # Derived, not asserted: the external surface a TRUSTED package can reach.
    reach, stack = set(), [c for c in deps if c in priv]
    while stack:
        n = stack.pop()
        if n in reach:
            continue
        reach.add(n)
        stack += deps.get(n, [])
    tcb_ext = {e for c in reach for e in ext.get(c, [])}
    all_ext = {e for c in deps for e in ext.get(c, [])}
    top = max(reach, key=lambda c: len(ext.get(c, [])))
    p.append(text(PAD, H - 56,
                  f"The dependency closure of a «trusted» package covers {len(reach)} of the "
                  f"{len(deps)} workspace packages and {len(tcb_ext)} of the {len(all_ext)} "
                  f"direct external crates — {len(ext[top])} through {top} alone.",
                  11, "600", fill=WARN))
    p.append(text(PAD, H - 41,
                  "Closure is not TCB membership (see the component view) — but it is the code "
                  "a privileged package can reach, so it is the surface that matters.",
                  10, fill=MUTED))
    p.append(footer(W, H, f"source: cargo metadata (normal deps) · {prov}"))

    p = [text(PAD, 44, "Workspace packages and their dependencies", 16, "600"),
         text(PAD, 64, "Every package in the workspace, layered by what it depends on. "
                       "Grey text inside a package is its DIRECT external crates.", 11, fill=MUTED),
         text(PAD, 80, "Normal dependencies only — dev- and build-dependencies are excluded, "
                       "since they reach no shipped artifact. An edge is a DECLARED dependency: "
                       "a manifest entry with no use site still draws one.", 11, fill=MUTED)] + p
    return svg(W, H, "\n".join(p),
               "Maknae workspace package diagram",
               "UML package diagram of the Maknae workspace, layered by dependency.")


# --- D5: the fs.read path, UML 2.5.1 sequence diagram (~ DoDAF SV-10c) ----

def d5_readpath(prov: str) -> str:
    """Where a read crosses a trust boundary, and by what mechanism.

    UML 2.5.1 sequence diagram: lifelines with execution occurrences, filled
    arrowhead for a synchronous call (17.4.4), open arrowhead on a dashed line
    for a reply. Steps are numbered so the notes can key to them -- eight UML
    note symbols on one diagram would cost more legibility than they buy.
    """
    doc = tomllib.loads((OUT / "read-path.toml").read_text())
    parts, steps = doc["participant"], doc["step"]
    check_evidence(steps, "evidence", "read-path.toml")
    idx = {p["id"]: i for i, p in enumerate(parts)}

    LEFT, PITCH, HEAD, ROW = 92, 170, 150, 44
    xs = [LEFT + i * PITCH for i in range(len(parts))]
    W = xs[-1] + 100
    body_h = HEAD + len(steps) * ROW + 26
    notes = [(i + 1, s["note"]) for i, s in enumerate(steps) if s.get("note")]
    H = body_h + 34 + len(notes) * 27 + 58

    style = {"actor":    (PLAIN_FILL, PLAIN_LINE, INK),
             "untrusted": ("#FDEEE9", WARN, "#7A2415"),
             "os":       (OK_FILL, OK_LINE, "#04342C"),
             "trusted":  (TRUST_FILL, TRUST_LINE, TRUST_INK)}

    p = ['<defs>'
         f'<marker id="call" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" '
         f'markerHeight="8" orient="auto-start-reverse">'
         f'<path d="M 0 1 L 9 5 L 0 9 z" fill="{INK}"/></marker>'
         f'<marker id="rep" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" '
         f'markerHeight="8" orient="auto-start-reverse">'
         f'<path d="M 0 1 L 9 5 L 0 9" fill="none" stroke="{MUTED}" '
         f'stroke-width="1.1"/></marker></defs>']

    # the trust boundary, behind the lifelines
    bx = 0
    for i, pa in enumerate(parts):
        if pa.get("boundary_before"):
            bx = (xs[i] + xs[i - 1]) / 2
    if bx:
        p.append(f'<rect x="{bx}" y="{HEAD-34}" width="{W-bx}" height="{body_h-HEAD+46}" '
                 f'fill="{TRUST_FILL}" opacity="0.35"/>')
        p.append(f'<line x1="{bx}" y1="{HEAD-34}" x2="{bx}" y2="{body_h+12}" '
                 f'stroke="{WARN}" stroke-width="1.2" stroke-dasharray="7 4"/>')
        p.append(text(bx - 8, HEAD - 40, "untrusted", 10, "600", fill=WARN, anchor="end"))
        p.append(text(bx + 8, HEAD - 40, "TRUST BOUNDARY — trust plane", 10, "600", fill=WARN))

    # lifelines
    for i, pa in enumerate(parts):
        fill, line, ink = style[pa["kind"]]
        x, bw = xs[i], 150
        p.append(box(x - bw / 2, HEAD - 28, bw, 34, fill, line, rx=4))
        p.append(text(x, HEAD - 14, pa["label"], 10.5, "600", fill=ink, anchor="middle"))
        p.append(text(x, HEAD - 3, pa["stereo"], 8, fill=line, anchor="middle"))
        p.append(f'<line x1="{x}" y1="{HEAD+6}" x2="{x}" y2="{body_h}" stroke="{MUTED}" '
                 f'stroke-width="0.7" stroke-dasharray="3 4"/>')

    # messages
    for n, s in enumerate(steps):
        y = HEAD + 34 + n * ROW
        a, b = xs[idx[s["from"]]], xs[idx[s["to"]]]
        rep = s["kind"] == "reply"
        stroke, dash = (MUTED, ' stroke-dasharray="5 3"') if rep else (INK, "")
        mark = "rep" if rep else "call"
        if s["kind"] == "self":
            p.append(f'<path d="M {a} {y-6} h 30 v 20 h -30" fill="none" stroke="{stroke}" '
                     f'stroke-width="1"{dash} marker-end="url(#{mark})"/>')
            # A self-message on a right-hand lifeline can run its evidence off
            # the canvas -- fully-qualified paths are long. Flip it to the left
            # of the lifeline when it will not fit to the right.
            need = max(len(f'{n+1}. {s["label"]}') * 5.6,
                       len(s.get("evidence", "")) * 4.6)
            if a + 40 + need > W - 24:
                lx, anc = a - 40, "end"
            else:
                lx, anc = a + 40, "start"
        else:
            p.append(f'<line x1="{a}" y1="{y+4}" x2="{b}" y2="{y+4}" stroke="{stroke}" '
                     f'stroke-width="1"{dash} marker-end="url(#{mark})"/>')
            lx, anc = (a + b) / 2, "middle"
        p.append(text(lx, y - 2, f'{n+1}. {s["label"]}', 10,
                      "600" if not rep else "400", fill=INK if not rep else MUTED,
                      anchor=anc, halo="#FFFFFF"))
        if s.get("evidence"):
            p.append(text(lx, y + 15, s["evidence"], 7.5, fill=MUTED, anchor=anc,
                          mono=True, halo="#FFFFFF"))

    y = body_h + 44
    p.append(text(LEFT - 52, y, "Notes", 12, "600"))
    for num, nt in notes:
        y += 27
        p.append(text(LEFT - 52, y, f"{num}.", 9.5, "600", fill=WARN))
        p.append(text(LEFT - 32, y, nt, 9.5, fill=INK))

    p = [text(LEFT - 52, 44, "The fs.read path — boundary crossings", 16, "600"),
         text(LEFT - 52, 64, "One request, end to end. The OS appears TWICE because that is the "
              "whole of ADR-0009: the same kernel, asked by two different", 11, fill=MUTED),
         text(LEFT - 52, 79, "principals, answers differently — and only the subject's answer may "
              "authorize a read. Each step names the code that implements it.", 11, fill=MUTED)] + p
    p.append(footer(W, H, f"source: {content_stamp('design/diagrams/read-path.toml')}"))
    return svg(W, H, "\n".join(p), "Maknae fs.read boundary crossings",
               "UML sequence diagram of the Maknae fs.read path across the trust boundary.")


def main() -> None:
    gates, ws = gate_facts(), workspace()
    links = linkage(ws["bins"])
    cg = crate_graph()
    prov = provenance()
    for name, content in [
        ("generated-tcb-components.svg", d1_tcb(gates, ws, links, prov)),
        ("generated-crate-binary-matrix.svg", d2_matrix(gates, ws, links, prov)),
        ("generated-standards-profile.svg", stdv1(prov)),
        ("generated-workspace-packages.svg", d4_packages(gates, cg, prov)),
        ("generated-read-path.svg", d5_readpath(prov)),
    ]:
        (OUT / name).write_text(content)
        print(f"  wrote design/diagrams/{name}")
    print(f"  provenance: {prov}")


if __name__ == "__main__":
    main()
