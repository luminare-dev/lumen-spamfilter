#!/usr/bin/env python3
"""Embed the rule catalog and the built-in data into editor/settings.html (between markers).

The editor page is self-contained (no external requests), so it carries a copy of
lumen_spamfilter/defaults.py, catalog.py and the pattern constants. tests/test_editor_parity.py
fails when the embedded copy is stale; run this script after changing those files.

Usage: python3 scripts/build_editor.py [--check]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lumen_spamfilter import __version__, catalog, defaults, patterns, render_rspamd  # noqa: E402

PAGE = ROOT / "editor" / "settings.html"
BLOCK = re.compile(r'(<script type="application/json" id="lumen-data">)\n.*?\n(</script>)', re.S)


def data() -> dict:
    return {
        "version": __version__,
        "marker": render_rspamd.MARKER,
        "map_dir": render_rspamd.MAP_DIR,
        "map_ref": render_rspamd.MAP_REF,
        "group": catalog.GROUP,
        "policy_group": catalog.POLICY_GROUP,
        "rules": catalog.RULES,
        "classes": catalog.CLASSES,
        "defaults": {
            "strong": defaults.PHARMA_STRONG, "weak": defaults.PHARMA_WEAK, "subject": defaults.PHARMA_SUBJECT,
            "brands": defaults.BRANDS, "phishing": defaults.PHISHING,
            "tlds_high": defaults.TLDS_HIGH, "tlds_medium": defaults.TLDS_MEDIUM,
        },
        "patterns": {
            "SEP": patterns.SEP, "INVISIBLE": patterns.INVISIBLE, "START": patterns.START,
            "LOOKALIKES": patterns.LOOKALIKES, "UMLAUTS": patterns.UMLAUTS, "PLAIN_UMLAUTS": patterns.PLAIN_UMLAUTS,
        },
        "paths": {"sieve_dir": "/var/lib/lumen-spamfilter/sieve", "imapsieve_dir": "/var/lib/lumen-spamfilter/imapsieve",
                  "pipe_dir": "/usr/local/lib/lumen-spamfilter/sieve-pipe", "rspamc": "/usr/bin/rspamc"},
    }


def embedded() -> str:
    # "</" never appears inside the JSON, so the script element cannot be closed early.
    return json.dumps(data(), ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="exit 1 if the page is out of date")
    args = ap.parse_args(argv)
    text = PAGE.read_text(encoding="utf-8")
    if not BLOCK.search(text):
        print("editor/settings.html has no lumen-data block", file=sys.stderr)
        return 2
    new = BLOCK.sub(lambda m: m.group(1) + "\n" + embedded() + "\n" + m.group(2), text, count=1)
    if args.check:
        if new != text:
            print("editor/settings.html is out of date: run python3 scripts/build_editor.py", file=sys.stderr)
            return 1
        return 0
    PAGE.write_text(new, encoding="utf-8")
    print("editor/settings.html updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
