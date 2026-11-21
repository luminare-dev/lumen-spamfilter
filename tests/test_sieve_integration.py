"""Run the generated Sieve scripts with Pigeonhole's sieve-test (CI job "sieve").

Skipped where sieve-test is missing, unless LUMEN_SPAMFILTER_REQUIRE_SIEVE=1 (CI sets it). sieve-test
must not run as root (it refuses mail access for UID 0).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lumen_spamfilter import config, render_sieve  # noqa: E402

REQUIRED = os.environ.get("LUMEN_SPAMFILTER_REQUIRE_SIEVE") == "1"
AVAILABLE = shutil.which("sieve-test") is not None and os.geteuid() != 0

CFG = """
[[mailbox]]
address = "a@example.com"
[[mailbox]]
address = "b@example.com"
threshold = 4.5
allow_senders = ["friend@example.net", "example.org"]
block_senders = ["blocked.invalid", "x@example.net"]
[[mailbox]]
address = "c@example.com"
action = "redirect"
redirect_to = "spam@example.com"
[[mailbox]]
address = "d@example.com"
action = "redirect"
redirect_to = "spam@example.com"
keep_copy = true
folder = "Spam"
[[mailbox]]
address = "spam@example.com"
action = "keep"
"""

# (mailbox, From, X-Spam-Status or None, expected action words)
CASES = [
    ("a", "s@spam.invalid", "Yes, score=7.20", ["store message in folder: Junk"]),
    ("a", "s@spam.invalid", "No, score=5.99", ["store message in folder: INBOX"]),
    ("a", "s@spam.invalid", None, ["store message in folder: INBOX"]),
    ("a", "s@spam.invalid", "No, score=-3.10 [1.2.3.4]", ["store message in folder: INBOX"]),
    ("b", "s@spam.invalid", "No, score=4.50", ["store message in folder: Junk"]),
    ("b", "s@spam.invalid", "No, score=4.49", ["store message in folder: INBOX"]),
    ("b", "s@spam.invalid", "Yes, score=12.00", ["store message in folder: Junk"]),
    ("b", "s@spam.invalid", "No, score=-12.00", ["store message in folder: INBOX"]),
    ("b", "friend@example.net", "Yes, score=9.00", ["store message in folder: INBOX"]),
    ("b", "news@example.org", "Yes, score=9.00", ["store message in folder: INBOX"]),
    ("b", "a@blocked.invalid", None, ["store message in folder: Junk"]),
    ("b", "x@example.net", "No, score=0.10", ["store message in folder: Junk"]),
    ("c", "s@spam.invalid", "Yes, score=8.00", ["redirect message to: spam@example.com"]),
    ("c", "s@spam.invalid", "No, score=1.00", ["store message in folder: INBOX"]),
    ("d", "s@spam.invalid", "Yes, score=8.00", ["redirect message to: spam@example.com",
                                                "store message in folder: Spam"]),
    ("spam", "s@spam.invalid", "Yes, score=8.00", ["store message in folder: INBOX"]),
]


@unittest.skipUnless(AVAILABLE or REQUIRED, "sieve-test not available (or running as root)")
class SieveTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="lumen-sieve-"))
        (cls.tmp / "dovecot.conf").write_text(f"mail_location = maildir:{cls.tmp}/mail\n")
        cls.scripts = {}
        for rel, text in render_sieve.render(config.loads(CFG)).items():
            p = cls.tmp / rel.replace("/", "_")
            p.write_text(text)
            cls.scripts[rel.split("/")[1].removesuffix(".sieve")] = p

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_case(self, box: str, sender: str, status: str | None) -> str:
        msg = self.tmp / "msg.eml"
        hdr = f"X-Spam-Status: {status}\n" if status else ""
        msg.write_text(f"From: Test <{sender}>\nTo: {box}@example.com\nSubject: test\n{hdr}\nbody\n")
        res = subprocess.run(["sieve-test", "-c", str(self.tmp / "dovecot.conf"), str(self.scripts[box]), str(msg)],
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        return res.stdout

    def test_cases(self):
        for box, sender, status, expected in CASES:
            with self.subTest(box=box, sender=sender, status=status):
                out = self.run_case(box, sender, status)
                performed = out.split("Performed actions:", 1)[-1]
                for words in expected:
                    self.assertIn(words, performed)
                if expected == ["store message in folder: INBOX"]:
                    self.assertNotIn("Junk", performed)

    def test_imapsieve_scripts_compile(self):
        conf = self.tmp / "imapsieve.conf"
        conf.write_text(f"mail_location = maildir:{self.tmp}/mail\nplugin {{\n"
                        "  sieve_plugins = sieve_imapsieve sieve_extprograms\n"
                        "  sieve_global_extensions = +vnd.dovecot.pipe +vnd.dovecot.environment\n"
                        f"  sieve_pipe_bin_dir = {self.tmp}\n}}\n")
        for name, text in render_sieve.imapsieve_scripts().items():
            p = self.tmp / name
            p.write_text(text)
            res = subprocess.run(["sievec", "-c", str(conf), str(p), str(self.tmp / "out.svbin")],
                                 capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)


if __name__ == "__main__":
    unittest.main()
