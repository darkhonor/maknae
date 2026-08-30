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

import json
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


# --- SVG primitives -------------------------------------------------------

def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def text(x, y, s, size=12, weight="400", fill=INK, anchor="start", mono=False):
    fam = "ui-monospace, SFMono-Regular, Menlo, monospace" if mono else FONT
    return (f'<text x="{x}" y="{y}" text-anchor="{anchor}" font-family="{fam}" '
            f'font-size="{size}" font-weight="{weight}" fill="{fill}">{esc(s)}</text>')


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


def main() -> None:
    gates, ws = gate_facts(), workspace()
    links = linkage(ws["bins"])
    prov = provenance()
    for name, content in [
        ("generated-tcb-components.svg", d1_tcb(gates, ws, links, prov)),
        ("generated-crate-binary-matrix.svg", d2_matrix(gates, ws, links, prov)),
    ]:
        (OUT / name).write_text(content)
        print(f"  wrote design/diagrams/{name}")
    print(f"  provenance: {prov}")


if __name__ == "__main__":
    main()
