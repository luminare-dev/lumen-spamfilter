"""apply / rollback / install / uninstall against a fake KeyHelp tree with stub commands."""

from __future__ import annotations

import io
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lumen_spamfilter import cli  # noqa: E402

STUB = '#!/bin/sh\necho "$(basename "$0") $*" >> "{log}"\n{body}\n'


class FakeServer:
    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="lumen-test-"))
        self.log = self.root / "calls.log"
        for d in ("etc/keyhelp", "etc/dovecot/conf.keyhelp.d", "etc/rspamd/local.d", "etc/lumen-spamfilter",
                  "usr/bin", "usr/sbin"):
            (self.root / d).mkdir(parents=True)
        (self.root / "etc/rspamd/local.d/multimap.conf").write_text("# Created by KeyHelp.\n")
        for c in ("rspamc", "rspamadm", "doveconf", "sievec", "systemctl"):
            self.stub(c, "exit 0")
        shutil.copy(ROOT / "examples" / "config.toml", self.root / "etc/lumen-spamfilter/config.toml")

    def stub(self, name: str, body: str) -> None:
        p = self.root / ("usr/sbin" if name == "sendmail" else "usr/bin") / name
        p.write_text(STUB.format(log=self.log, body=body))
        p.chmod(0o755)

    def run(self, *args: str) -> tuple[int, str]:
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(out):
            try:
                code = cli.main(["--root", str(self.root), *args])
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else 1
        return code, out.getvalue()

    def calls(self) -> str:
        return self.log.read_text() if self.log.exists() else ""

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class DeployTest(unittest.TestCase):
    def setUp(self):
        self.s = FakeServer()
        self.addCleanup(self.s.close)
        self.regexp = self.s.root / "etc/rspamd/override.d/regexp.conf"
        self.sieve = self.s.root / "var/lib/lumen-spamfilter/sieve/example.com/postmaster.sieve"

    def test_dry_run_by_default(self):
        code, out = self.s.run("apply")
        self.assertEqual(code, 0, out)
        self.assertIn("dry run", out)
        self.assertFalse(self.regexp.exists())

    def test_apply_writes_tests_and_reloads(self):
        code, out = self.s.run("apply", "--write")
        self.assertEqual(code, 0, out)
        self.assertTrue(self.regexp.exists() and self.sieve.exists())
        calls = self.s.calls()
        self.assertIn("rspamadm --var=LOCAL_CONFDIR=", calls)
        self.assertIn("rspamadm configtest", calls)
        self.assertIn("sievec", calls)
        self.assertIn("systemctl reload rspamd", calls)
        self.assertEqual((self.s.root / "etc/rspamd/local.d/multimap.conf").read_text(), "# Created by KeyHelp.\n")
        code, out = self.s.run("apply")
        self.assertIn("already up to date", out)

    def test_staged_configtest_failure_writes_nothing(self):
        self.s.stub("rspamadm", 'echo "syntax error" >&2; exit 1')
        code, out = self.s.run("apply", "--write")
        self.assertEqual(code, 1)
        self.assertIn("nothing was written", out)
        self.assertFalse(self.regexp.exists())

    def test_live_check_failure_restores(self):
        self.s.stub("sievec", "exit 1")
        code, out = self.s.run("apply", "--write")
        self.assertEqual(code, 1, out)
        self.assertIn("restored", out)
        self.assertFalse(self.regexp.exists())
        self.assertNotIn("systemctl reload", self.s.calls())

    def test_foreign_file_is_a_conflict(self):
        foreign = self.s.root / "etc/rspamd/override.d/groups.conf"
        foreign.parent.mkdir(parents=True)
        foreign.write_text("group mine {}\n")
        code, out = self.s.run("apply", "--write")
        self.assertEqual(code, 1)
        self.assertIn("conflict", out)
        self.assertEqual(foreign.read_text(), "group mine {}\n")
        code, out = self.s.run("apply", "--write", "--adopt")
        self.assertEqual(code, 0, out)
        code, out = self.s.run("rollback", "--write")
        self.assertEqual(code, 0, out)
        self.assertEqual(foreign.read_text(), "group mine {}\n")

    def test_rollback_removes_created_files(self):
        self.s.run("apply", "--write")
        code, out = self.s.run("rollback", "--list")
        self.assertEqual(len(out.split()), 1)
        code, out = self.s.run("rollback", "--write")
        self.assertEqual(code, 0, out)
        self.assertFalse(self.regexp.exists())
        self.assertFalse(self.sieve.exists())

    def test_removed_mailbox_script_is_deleted(self):
        self.s.run("apply", "--write")
        cfgp = self.s.root / "etc/lumen-spamfilter/config.toml"
        cfgp.write_text(cfgp.read_text().replace('address = "postmaster@example.com"', 'address = "x@example.com"'))
        code, out = self.s.run("apply", "--write")
        self.assertEqual(code, 0, out)
        self.assertFalse(self.sieve.exists())
        self.assertTrue((self.sieve.parent / "x.sieve").exists())

    def test_install_and_uninstall(self):
        self.s.run("apply", "--write")
        code, out = self.s.run("install", "--write")
        self.assertEqual(code, 0, out)
        self.assertTrue((self.s.root / "etc/systemd/system/lumen-spamfilter-train.timer").exists())
        self.assertTrue((self.s.root / "usr/local/sbin/lumen-spamfilter").exists())
        code, out = self.s.run("uninstall", "--write")
        self.assertEqual(code, 0, out)
        left = [p for p in self.s.root.rglob("*") if p.is_file() and "backups" not in p.parts
                and p.parent.name not in ("bin", "sbin") and p.name != "calls.log"]
        self.assertEqual(sorted(str(p.relative_to(self.s.root)) for p in left),
                         ["etc/lumen-spamfilter/config.toml", "etc/rspamd/local.d/multimap.conf"])

    def test_install_refuses_without_keyhelp(self):
        shutil.rmtree(self.s.root / "etc/keyhelp")
        code, out = self.s.run("install", "--write")
        self.assertEqual(code, 1)
        self.assertIn("KeyHelp layout not found", out)

    def test_invalid_config(self):
        (self.s.root / "etc/lumen-spamfilter/config.toml").write_text("[delivery]\naction = 'delete'\n")
        code, out = self.s.run("check")
        self.assertEqual(code, 1)
        self.assertIn("delivery.action", out)


if __name__ == "__main__":
    unittest.main()
