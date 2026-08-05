#!/usr/bin/env python3
"""Scrape the public DoD/NARA CUI Registry into a versioned JSON data source.

This is a MAINTENANCE tool for the ``maknae-dcs-core`` crate, not shipped code.
The crate embeds the full CUI Registry so the decision engine never fetches at
decide-time (air-gapped target). Recognition is by ``category_marking``; the
rest of the emitted schema is inert provenance captured for completeness.

Source of truth (public HTML, no API):
    https://www.archives.gov/cui/registry/category-list

Design constraints:
    * Python 3.11+, **standard library only** (urllib + html.parser). No
      third-party deps (requests/bs4) so it runs anywhere with a base Python.
    * Resilient: archives.gov is hand-maintained HTML whose per-page layout
      varies. A missing optional field becomes ``null`` rather than a crash.
      Pages that 404 or expose no ``category_marking`` are logged to stderr
      and skipped (they cannot satisfy the required-field contract).
    * Deterministic output: categories sorted by ``(category_marking, name)``.

Usage:
    python3 scrape_cui_registry.py [--out PATH] [--delay SECONDS] [--verbose]

Writes ``data/cui-registry.json`` relative to the crate root by default.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
import time
import urllib.error
import urllib.request
from html.parser import HTMLParser
from html import unescape

BASE = "https://www.archives.gov"
CATEGORY_LIST_URL = f"{BASE}/cui/registry/category-list"
USER_AGENT = "maknae-dcs-core-cui-scraper/1.0 (+maintenance tool; stdlib urllib)"

# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


def fetch(url: str, *, retries: int = 3, timeout: int = 40) -> str:
    """GET ``url`` and return decoded HTML. Follows redirects (urllib default).

    archives.gov redirects ``.../category-detail/<slug>`` to the same URL with a
    ``.html`` suffix; urllib handles that transparently.
    """
    last_err: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
            return raw.decode("utf-8", errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as err:
            last_err = err
            log(f"  fetch attempt {attempt}/{retries} failed for {url}: {err}")
            time.sleep(1.0 * attempt)
    raise RuntimeError(f"failed to fetch {url}: {last_err}")


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Generic table / structure parser
# ---------------------------------------------------------------------------

_WS = re.compile(r"\s+")


def norm(text: str) -> str:
    """Collapse whitespace (incl. non-breaking spaces) and strip."""
    return _WS.sub(" ", unescape(text).replace("\xa0", " ")).strip()


def clean_or_none(text: str) -> str | None:
    n = norm(text)
    return n if n else None


class RegistryParser(HTMLParser):
    """Extract the pieces of a CUI Registry page we care about.

    Collects:
      * ``h1``            -- e.g. "CUI Category: Information Systems Vulnerability Information"
      * ``h3s``           -- e.g. ["Banner Marking: CUI", ...]
      * ``tables``        -- list[ list[row] ]; row = list[cell-text]
      * ``last_update``   -- footer "This page was last reviewed on ..." text

    Table parsing is generic so it survives layout drift between pages.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.h1: str | None = None
        self.h3s: list[str] = []
        self.tables: list[list[list[str]]] = []
        self.last_update: str | None = None

        self._stack: list[str] = []
        # capture buffers keyed by what we are currently inside
        self._in_h1 = False
        self._in_h3 = False
        self._h_buf: list[str] = []
        self._in_last_update = False
        self._lu_buf: list[str] = []

        # table state
        self._table: list[list[str]] | None = None
        self._row: list[str] | None = None
        self._cell: list[str] | None = None

    # -- tag handling -----------------------------------------------------
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._stack.append(tag)
        adict = {k: (v or "") for k, v in attrs}

        if tag == "h1":
            self._in_h1 = True
            self._h_buf = []
        elif tag == "h3":
            self._in_h3 = True
            self._h_buf = []
        elif tag == "table":
            self._table = []
        elif tag == "tr" and self._table is not None:
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []

        # footer last-reviewed marker (id="last-update")
        if adict.get("id") == "last-update":
            self._in_last_update = True
            self._lu_buf = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "h1" and self._in_h1:
            self.h1 = norm("".join(self._h_buf))
            self._in_h1 = False
        elif tag == "h3" and self._in_h3:
            self.h3s.append(norm("".join(self._h_buf)))
            self._in_h3 = False
        elif tag in ("td", "th") and self._cell is not None and self._row is not None:
            self._row.append(norm("".join(self._cell)))
            self._cell = None
        elif tag == "tr" and self._row is not None and self._table is not None:
            self._table.append(self._row)
            self._row = None
        elif tag == "table" and self._table is not None:
            self.tables.append(self._table)
            self._table = None

        if self._in_last_update and tag == "p":
            self.last_update = norm("".join(self._lu_buf))
            self._in_last_update = False

        # pop matching tag from stack (best effort)
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i] == tag:
                del self._stack[i]
                break

    def handle_data(self, data: str) -> None:
        if self._in_h1 or self._in_h3:
            self._h_buf.append(data)
        if self._cell is not None:
            self._cell.append(data)
        if self._in_last_update:
            self._lu_buf.append(data)


# ---------------------------------------------------------------------------
# Category list -> (slug, group, name)
# ---------------------------------------------------------------------------

# Match any anchor whose href contains a category-detail path. archives.gov is
# hand-maintained and emits two malformations we must tolerate:
#   * a trailing ".html" on some hrefs (e.g. ".../nuclear-security-related-info.html")
#   * a doubled path (".../category-detail/cui/registry/category-detail/privileged-safety-info")
# We therefore take the slug after the LAST "category-detail/" and rebuild a
# clean canonical URL, rather than trusting the raw href.
_DETAIL_ANCHOR = re.compile(
    r'<a\s[^>]*href="([^"]*?category-detail/[^"]+?)"[^>]*>(.*?)</a>', re.I | re.S
)
_SLUG_RE = re.compile(r"^[a-z0-9-]+$")


def _slug_from_href(href: str) -> str | None:
    """Extract a clean lowercase slug from a (possibly malformed) detail href."""
    tail = href.rsplit("category-detail/", 1)[-1]
    tail = tail.split("#", 1)[0].split("?", 1)[0].strip("/")
    if tail.endswith(".html"):
        tail = tail[:-5]
    tail = tail.strip("/")
    return tail if _SLUG_RE.match(tail) else None


def parse_category_list(html: str) -> tuple[list[str], list[dict[str, str]]]:
    """Return (sorted group names, [{slug, url, group, list_name}, ...]).

    The category-list page renders a two-column table:
        Organizational Index Grouping | CUI Categories (<ul> of detail links)
    We walk each row, take the group label from the first cell, and associate
    every detail link in that row with it.
    """
    # Isolate the first data table (the categories index).
    start = html.find("Organizational Index Grouping")
    end = html.find("</table>", start)
    if start == -1 or end == -1:
        raise RuntimeError("could not locate category index table on category-list page")
    segment = html[start:end]

    groups: list[str] = []
    entries: list[dict[str, str]] = []
    seen: set[str] = set()

    # Split into rows; each row has a leading group cell then a cell of links.
    for row_html in re.split(r"<tr[^>]*>", segment):
        tds = re.findall(r"<td[^>]*>(.*?)</td>", row_html, re.S | re.I)
        if len(tds) < 2:
            continue
        group = norm(re.sub(r"<[^>]+>", " ", tds[0]))
        if not group or group.lower() == "organizational index grouping":
            continue
        links_cell = tds[1]
        found = False
        for m in _DETAIL_ANCHOR.finditer(links_cell):
            slug = _slug_from_href(m.group(1))
            if not slug:
                continue
            found = True
            list_name = norm(re.sub(r"<[^>]+>", " ", m.group(2)))
            if slug in seen:
                continue
            seen.add(slug)
            entries.append(
                {
                    "slug": slug,
                    # Canonical URL, not the raw href (which may be malformed).
                    "url": f"{BASE}/cui/registry/category-detail/{slug}",
                    "group": group,
                    "list_name": list_name,
                }
            )
        if found and group not in groups:
            groups.append(group)

    return sorted(groups), entries


# ---------------------------------------------------------------------------
# Detail page -> category dict
# ---------------------------------------------------------------------------

_H1_PREFIX = re.compile(r"^CUI Category:\s*", re.I)
_BANNER_PREFIX = re.compile(r"^Banner Marking(?:s)?:\s*", re.I)
_LAST_REVIEWED = re.compile(r"last reviewed on\s+(.+?)\.", re.I)


def _label_key(cell: str) -> str:
    return norm(cell).rstrip(":").strip().lower()


def parse_detail(html: str, url: str, group: str, list_name: str) -> dict | None:
    """Parse a category-detail page into the emitted schema shape.

    Returns ``None`` (and logs) if the page exposes no ``category_marking`` --
    such a page cannot satisfy the required-field contract.
    """
    p = RegistryParser()
    p.feed(html)

    # name: prefer H1 ("CUI Category: <name>"); fall back to the list anchor text.
    name = None
    if p.h1:
        name = norm(_H1_PREFIX.sub("", p.h1))
    if not name:
        name = list_name or None

    # banner_marking: first H3 shaped "Banner Marking: <marking>".
    banner_marking = None
    for h3 in p.h3s:
        if _BANNER_PREFIX.match(h3):
            banner_marking = norm(_BANNER_PREFIX.sub("", h3)) or None
            break

    # Key/value fields from any 2-column table row.
    category_marking = None
    alternative_banner_marking = None
    description = None
    for table in p.tables:
        for row in table:
            if len(row) != 2:
                continue
            key = _label_key(row[0])
            val = clean_or_none(row[1])
            if key == "category marking" or key.startswith("category marking"):
                category_marking = val or category_marking
            elif key.startswith("alternative banner marking"):
                alternative_banner_marking = val or alternative_banner_marking
            elif key.startswith("category description") or key == "description":
                description = val or description

    # Authorities table(s): header first cell contains "Safeguarding".
    authorities: list[dict] = []
    for table in p.tables:
        if not table:
            continue
        header = table[0]
        hjoin = " ".join(header).lower()
        if "safeguarding" not in hjoin:
            continue
        # Map columns by header text; default to canonical 4-column order.
        cols = [norm(h).lower() for h in header]

        def find_col(*needles: str) -> int | None:
            for i, c in enumerate(cols):
                if any(n in c for n in needles):
                    return i
            return None

        i_cit = find_col("safeguarding", "dissemination", "authority")
        i_cls = find_col("basic or", "basic", "specified")
        i_ban = find_col("banner")
        i_san = find_col("sanction")
        for drow in table[1:]:
            if not any(norm(c) for c in drow):
                continue

            def cell(idx: int | None) -> str | None:
                if idx is None or idx >= len(drow):
                    return None
                return clean_or_none(drow[idx])

            authorities.append(
                {
                    "citation": cell(i_cit),
                    "classification": cell(i_cls),
                    "banner_marking": cell(i_ban),
                    "sanctions": cell(i_san),
                }
            )

    # last_reviewed from footer text.
    last_reviewed = None
    if p.last_update:
        m = _LAST_REVIEWED.search(p.last_update)
        if m:
            last_reviewed = norm(m.group(1))

    if not category_marking:
        log(f"  SKIP {url}: no category_marking found (name={name!r})")
        return None
    if not name:
        log(f"  SKIP {url}: no name found (marking={category_marking!r})")
        return None

    return {
        "name": name,
        "category_marking": category_marking,
        "banner_marking": banner_marking,
        "alternative_banner_marking": alternative_banner_marking,
        "group": group,
        "description": description,
        "authorities": authorities,
        "last_reviewed": last_reviewed,
        "source_url": url,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def default_out_path() -> str:
    import os

    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "data", "cui-registry.json"))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Scrape the NARA CUI Registry to JSON.")
    ap.add_argument("--out", default=default_out_path(), help="output JSON path")
    ap.add_argument("--delay", type=float, default=0.25, help="politeness delay (s)")
    ap.add_argument("--verbose", action="store_true", help="log each category")
    args = ap.parse_args(argv)

    today = datetime.date.today().isoformat()

    log(f"Fetching category list: {CATEGORY_LIST_URL}")
    list_html = fetch(CATEGORY_LIST_URL)
    groups, entries = parse_category_list(list_html)
    log(f"Discovered {len(groups)} groups, {len(entries)} category detail links.")

    categories: list[dict] = []
    failed: list[str] = []
    skipped: list[str] = []

    for i, entry in enumerate(entries, 1):
        url = entry["url"]
        if args.verbose:
            log(f"[{i}/{len(entries)}] {entry['slug']}  ({entry['group']})")
        try:
            html = fetch(url)
        except Exception as err:  # noqa: BLE001 - resilient by design
            log(f"  FETCH FAILED {url}: {err}")
            failed.append(entry["slug"])
            continue
        try:
            cat = parse_detail(html, url, entry["group"], entry["list_name"])
        except Exception as err:  # noqa: BLE001 - never crash the whole run
            log(f"  PARSE FAILED {url}: {err}")
            failed.append(entry["slug"])
            continue
        if cat is None:
            skipped.append(entry["slug"])
        else:
            categories.append(cat)
        time.sleep(args.delay)

    # Deterministic order. Primary key is category_marking (the recognition
    # key); name + source_url break ties so distinct list slugs that share a
    # marking (e.g. NARA-aliased pages) always land in a stable order.
    categories.sort(key=lambda c: (c["category_marking"], c["name"], c["source_url"]))

    doc = {
        "version": today,
        "source": "archives.gov/cui/registry",
        "retrieved": today,
        "groups": groups,
        "categories": categories,
    }

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    log("")
    log(f"WROTE {args.out}")
    log(f"  groups:     {len(groups)}")
    log(f"  categories: {len(categories)}")
    log(f"  skipped (no marking): {len(skipped)} -> {skipped}")
    log(f"  failed (fetch/parse): {len(failed)} -> {failed}")
    markings = {c["category_marking"] for c in categories}
    log(f"  ISVI present: {'ISVI' in markings}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
