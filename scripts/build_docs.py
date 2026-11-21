#!/usr/bin/env python3
"""Write docs/rules.md from the rule catalog and the built-in data (--check: exit 1 if stale)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lumen_spamfilter import catalog, defaults  # noqa: E402

OUT = ROOT / "docs" / "rules.md"

INTRO = """# Rules

Generated from `lumen_spamfilter/catalog.py` and `lumen_spamfilter/defaults.py` by
`python3 scripts/build_docs.py`; do not edit by hand.

Every rule is an Rspamd symbol named `LUMEN_*`. The scores below are the defaults; change any of
them in the `[scores]` table of the configuration. On KeyHelp the actions are greylist at 4, add
header at 6 and reject at 15. The content rules (group `lumen_spamfilter`) are capped at
`rspamd.group_max_score` (default 12), so they alone never reach the reject score: a reject still
needs evidence from Rspamd's own rules. The allow and block lists (group `lumen_policy`) are not
capped.

Words are matched obfuscation-tolerant: up to two inserted separators between letters (space,
`-`, `_`, `.`, `*`, `·`, `|`, `~`, `+`, soft hyphen, zero-width space/joiner, word joiner, byte
order mark), digit and symbol look-alikes (`0` for o, `3` for e, `1` `!` `|` for i, `5` `$` for
s, `@` `4` for a, `7` for t), Cyrillic look-alike letters, and `ae`/`oe`/`ue`/`ss` or combining
marks for umlauts and ß.

Rules that are informational (score 0) only feed the composite rules next to them.
"""


def table(rows: list[dict]) -> list[str]:
    out = ["| Rule | Score | Type | What it matches |", "|---|---|---|---|"]
    for r in rows:
        out.append(f"| `{r['symbol']}` | {r['score']:g} | {r['kind']} | {r['description'].replace('|', '/')} |")
    return out


def words(items: list[str]) -> str:
    return ", ".join(f"`{w}`" for w in items)


def render() -> str:
    lines = [INTRO]
    for cls, title in catalog.CLASSES.items():
        lines += [f"## {title}", ""] + table([r for r in catalog.RULES if r["class"] == cls]) + [""]
    lines += ["## Built-in data", "", "### Pharma words", "",
              f"Strong (score on their own): {words(defaults.PHARMA_STRONG)}.", "",
              f"Weak (three or more in the body): {words(defaults.PHARMA_WEAK)}.", "",
              f"Subject-only words: {words(defaults.PHARMA_SUBJECT)}.", "",
              "Add words with `[terms] strong`, `weak` and `subject`; `replace_defaults = true` drops these lists.", "",
              "### Brands", "",
              "A display name with one of these names, from a domain outside the listed ones, scores "
              "`LUMEN_BRAND_SPOOF`. Banks and insurers that mail from regional domains need those domains "
              "added (`[[brands]]` with the same name extends the entry), or the domain on the verified allowlist.",
              "", "| Brand | Domains | Link tokens |", "|---|---|---|"]
    for b in defaults.BRANDS:
        lines.append(f"| {b['name']} | {', '.join(b['domains'])} | {', '.join(b['url_tokens']) or '-'} |")
    lines += ["", "### Phishing phrases", "",
              "Each rule needs one alternative from every part, in the subject or in the body "
              "(case-insensitive regular expressions).", ""]
    for sym, parts in defaults.PHISHING.items():
        lines.append(f"- `{sym}`: " + " **and** ".join("(" + " / ".join(f"`{a}`" for a in p) + ")" for p in parts))
    lines += ["", "### Top-level domains", "", f"High risk: {words(defaults.TLDS_HIGH)}.", "",
              f"Medium risk: {words(defaults.TLDS_MEDIUM)}.", "",
              "Change them with `[tlds] extra_high`, `extra_medium` and `remove`.", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    text = render()
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            print("docs/rules.md is out of date: run python3 scripts/build_docs.py", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text, encoding="utf-8")
    print("docs/rules.md written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
