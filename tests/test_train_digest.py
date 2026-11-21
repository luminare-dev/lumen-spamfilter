"""Bayes training and digest against a fake Maildir tree (synthetic messages, stub rspamc/sendmail)."""

from __future__ import annotations

import os
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lumen_spamfilter import config, digest, train  # noqa: E402
from lumen_spamfilter.layout import Layout  # noqa: E402
from tests.test_deploy import FakeServer  # noqa: E402

CFG = """
[[mailbox]]
address = "user@example.com"
digest = true
[digest]
from = "postmaster@example.com"
[training]
ham_min_age_days = 3
"""


def msg(subject: str, score: str = "7.10") -> bytes:
    return (f"From: Sender <a@spam.invalid>\nTo: user@example.com\nSubject: {subject}\n"
            f"X-Spam-Status: Yes, score={score}\n\nbody\n").encode()


class TrainDigestTest(unittest.TestCase):
    def setUp(self):
        self.s = FakeServer()
        self.addCleanup(self.s.close)
        self.lay = Layout(str(self.s.root))
        self.cfg = config.loads(CFG)
        md = self.s.root / "var/mail/vhosts/example.com/user"
        old = time.time() - 10 * 86400
        self.files = {
            "junk": md / ".Junk/cur/1.host:2,S", "junk_new": md / ".Junk/new/2.host",
            "ham_old_seen": md / "cur/3.host:2,S", "ham_old_unseen": md / "cur/4.host:2,",
            "ham_fresh": md / "cur/5.host:2,S",
        }
        for key, p in self.files.items():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(msg(key))
            if key.startswith("ham_old"):
                os.utime(p, (old, old))
        self.s.stub("rspamc", "cat > /dev/null; exit 0")
        self.s.stub("sendmail", 'cat > "$(dirname "$0")/../../sent.eml"; exit 0')

    def test_candidates(self):
        found = sorted((c, p.name) for c, p in train.candidates(self.cfg, self.lay))
        self.assertEqual(found, [("ham", "3.host:2,S"), ("spam", "1.host:2,S"), ("spam", "2.host")])

    def test_training_is_idempotent(self):
        stats = train.run(self.cfg, self.lay, write=False, log=lambda *_: None)
        self.assertEqual(stats["pending"], 3)
        stats = train.run(self.cfg, self.lay, write=True, log=lambda *_: None)
        self.assertEqual((stats["spam"], stats["ham"]), (2, 1))
        self.assertEqual(self.s.calls().count("learn_"), 3)
        stats = train.run(self.cfg, self.lay, write=True, log=lambda *_: None)
        self.assertEqual((stats["spam"], stats["ham"], stats["skipped"]), (0, 0, 3))
        self.assertEqual(self.s.calls().count("learn_"), 3)

    def test_moved_message_is_relearned(self):
        train.run(self.cfg, self.lay, write=True, log=lambda *_: None)
        src = self.files["ham_old_seen"]
        dest = src.parent.parent / ".Junk/cur" / src.name
        src.rename(dest)
        stats = train.run(self.cfg, self.lay, write=True, log=lambda *_: None)
        self.assertEqual(stats["spam"], 1)

    def test_already_learned_counts_as_done(self):
        self.s.stub("rspamc", 'cat > /dev/null; echo "<x> has been already learned as spam, ignore it"; exit 1')
        stats = train.run(self.cfg, self.lay, write=True, log=lambda *_: None)
        self.assertEqual(stats["failed"], 0)

    def test_digest(self):
        sent = digest.run(self.cfg, self.lay, write=True, log=lambda *_: None)
        self.assertEqual(sent, 1)
        body = (self.s.root / "sent.eml").read_text()
        self.assertIn("Subject: Spam digest: 2 message(s) in Junk", body)
        self.assertIn("junk_new", body)
        self.assertNotIn("http", body.split("\n\n", 1)[1])

    def test_digest_strips_control_characters(self):
        self.assertEqual(digest.clean("a​b\x1b[31m  c", 20), "ab[31m c")


if __name__ == "__main__":
    unittest.main()
