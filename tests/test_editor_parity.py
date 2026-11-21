"""The editor page: embedded data is current, it makes no requests, and its JavaScript generator writes
exactly the files the Python generator writes (run with node; CI sets LUMEN_SPAMFILTER_REQUIRE_NODE=1)."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lumen_spamfilter import config, render_dovecot, render_rspamd, render_sieve  # noqa: E402
from lumen_spamfilter.layout import Layout  # noqa: E402
from tests.test_sieve_integration import CFG as SIEVE_CFG  # noqa: E402

PAGE = ROOT / "editor" / "settings.html"
NODE = shutil.which("node")
REQUIRED = os.environ.get("LUMEN_SPAMFILTER_REQUIRE_NODE") == "1"

EXTRA = SIEVE_CFG + """
[rspamd]
local_domains = ["example.org"]
group_max_score = 10.5
[scores]
LUMEN_BRAND_SPOOF = 5.25
LUMEN_ALLOW_VERIFIED = -6
[terms]
strong = ["wundermittel"]
weak = ["schnell abnehmen"]
[[brands]]
name = "Example Bank"
domains = ["bank.example.com"]
url_tokens = ["examplebank"]
[[brands]]
name = "PayPal"
domains = ["pay.example.net"]
[tlds]
extra_high = ["example"]
remove = ["xyz"]
[allow]
verified_domains = ["example.net"]
[block]
senders = ["bad@spam.invalid"]
domains = ["spam.invalid"]
[training]
imapsieve = true
spam_folders = ["Spam"]
[digest]
from = "postmaster@example.com"
"""


def python_files(text: str) -> dict:
    cfg = config.loads(text)
    files = {f"rspamd/{k}": v for k, v in render_rspamd.render(cfg).items()}
    files.update({f"sieve/{k}": v for k, v in render_sieve.render(cfg).items()})
    files["dovecot/local.conf"] = render_dovecot.render(cfg, Layout("/").paths_for_render())
    return files


class PageTest(unittest.TestCase):
    def test_embedded_data_is_current(self):
        res = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_editor.py"), "--check"],
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_rules_doc_is_current(self):
        res = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_docs.py"), "--check"],
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_no_external_requests(self):
        html = PAGE.read_text(encoding="utf-8")
        self.assertNotRegex(html, r"""(?:src|href)\s*=\s*["']?(?:https?:)?//""")
        for word in ("fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "import("):
            self.assertNotIn(word, html)
        self.assertIn("default-src 'none'", html)


@unittest.skipUnless(NODE or REQUIRED, "node is not installed")
class ParityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        html = PAGE.read_text(encoding="utf-8")
        data = re.search(r'<script type="application/json" id="lumen-data">\n(.*?)\n</script>', html, re.S).group(1)
        gen = re.search(r'<script id="lumen-gen">\n(.*?)</script>', html, re.S).group(1)
        cls.tmp = Path(tempfile.mkdtemp(prefix="lumen-editor-"))
        (cls.tmp / "gen.js").write_text(f"var LUMEN_DATA = {data};\n{gen}", encoding="utf-8")
        (cls.tmp / "run.js").write_text(
            "const g = require('./gen.js'); const fs = require('fs');\n"
            "const r = g.renderAll(fs.readFileSync(process.argv[2], 'utf8'));\n"
            "const rt = g.renderAll(g.writeToml(g.parseToml(fs.readFileSync(process.argv[2], 'utf8'))));\n"
            "process.stdout.write(JSON.stringify({direct: r, roundtrip: rt}));\n", encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def js(self, text: str) -> dict:
        cfgp = self.tmp / "config.toml"
        cfgp.write_text(text, encoding="utf-8")
        res = subprocess.run([NODE or "node", str(self.tmp / "run.js"), str(cfgp)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads(res.stdout)

    def assert_same(self, text: str):
        expected = python_files(text)
        out = self.js(text)
        for key in ("direct", "roundtrip"):
            got = out[key]
            self.assertNotIn("errors", got, got.get("errors"))
            self.assertEqual(sorted(got["files"]), sorted(expected), key)
            for name, content in expected.items():
                self.assertEqual(got["files"][name], content, f"{key}: {name}")

    def test_example_config(self):
        self.assert_same((ROOT / "examples" / "config.toml").read_text(encoding="utf-8"))

    def test_corpus_config(self):
        self.assert_same((ROOT / "tests" / "corpus" / "config.toml").read_text(encoding="utf-8"))

    def test_feature_rich_config(self):
        self.assert_same(EXTRA)

    def test_invalid_config_is_rejected_by_both(self):
        bad = '[[mailbox]]\naddress = "a@example.com"\naction = "redirect"\n[scores]\nLUMEN_NOPE = 1\n'
        with self.assertRaises(config.ConfigError):
            config.loads(bad)
        errors = self.js(bad)["direct"]["errors"]
        self.assertTrue(any("redirect_to" in e for e in errors), errors)
        self.assertTrue(any("LUMEN_NOPE" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
