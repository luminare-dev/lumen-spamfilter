"""Server layout: where KeyHelp keeps Rspamd, Dovecot and the mailboxes, and the tools to call.

Every path can be moved below a test root (--root), which the tests use with stub commands.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

DEFAULTS = {
    "config": "/etc/lumen-spamfilter/config.toml",
    "rspamd_confdir": "/etc/rspamd",
    "dovecot_local_conf": "/etc/dovecot/local.conf",
    "dovecot_keyhelp_dir": "/etc/dovecot/conf.keyhelp.d",
    "keyhelp_dir": "/etc/keyhelp",
    "state_dir": "/var/lib/lumen-spamfilter",
    "sieve_dir": "/var/lib/lumen-spamfilter/sieve",
    "imapsieve_dir": "/var/lib/lumen-spamfilter/imapsieve",
    "backup_dir": "/var/lib/lumen-spamfilter/backups",
    "pipe_dir": "/usr/local/lib/lumen-spamfilter/sieve-pipe",
    "prefix": "/opt/lumen-spamfilter",
    "bin_link": "/usr/local/sbin/lumen-spamfilter",
    "systemd_dir": "/etc/systemd/system",
    "mail_location": "/var/mail/vhosts/%d/%n",
    "rspamc": "/usr/bin/rspamc",
    "rspamadm": "/usr/bin/rspamadm",
    "doveconf": "/usr/bin/doveconf",
    "sievec": "/usr/bin/sievec",
    "systemctl": "/usr/bin/systemctl",
    "sendmail": "/usr/sbin/sendmail",
}
COMMANDS = ("rspamc", "rspamadm", "doveconf", "sievec", "systemctl", "sendmail")


class Layout:
    def __init__(self, root: str = "/", overrides: dict | None = None):
        self.root = Path(root)
        values = dict(DEFAULTS)
        values.update(overrides or {})
        self.values = values

    def path(self, key: str) -> Path:
        value = self.values[key]
        return self.root / value.lstrip("/") if str(self.root) != "/" else Path(value)

    def cmd(self, key: str) -> str:
        return str(self.path(key))

    def paths_for_render(self) -> dict:
        """Paths as the server sees them (written into generated files, never test-rooted)."""
        return {k: self.values[k] for k in ("sieve_dir", "imapsieve_dir", "pipe_dir", "rspamc")}

    def run(self, key: str, *args: str, check: bool = False) -> subprocess.CompletedProcess:
        return subprocess.run([self.cmd(key), *args], capture_output=True, text=True, check=check)

    def run_input(self, key: str, data: bytes, *args: str) -> subprocess.CompletedProcess:
        res = subprocess.run([self.cmd(key), *args], input=data, capture_output=True)
        return subprocess.CompletedProcess(res.args, res.returncode, res.stdout.decode("utf-8", "replace"),
                                           res.stderr.decode("utf-8", "replace"))

    # --- detection -------------------------------------------------------------------------

    def is_keyhelp(self) -> bool:
        return self.path("keyhelp_dir").is_dir() and self.path("dovecot_keyhelp_dir").is_dir()

    def doveconf(self, *args: str) -> str | None:
        try:
            res = self.run("doveconf", *args)
        except OSError:
            return None
        return res.stdout.strip() if res.returncode == 0 else None

    def detect_mail_location(self) -> str:
        loc = self.doveconf("-h", "mail_location")
        if loc:
            m = re.match(r"^maildir:([^:]+)", loc)
            if m and "%d" in m.group(1) and "%n" in m.group(1):
                return m.group(1)
        return self.values["mail_location"]

    def detect_dovecot(self, sieve_path: str) -> dict:
        """Current Dovecot values the drop-in has to extend instead of replace."""
        out: dict = {}
        key = "sieve_before"
        for n in ["", "2", "3", "4", "5", "6", "7", "8", "9"]:
            value = self.doveconf("-h", f"plugin/sieve_before{n}") or ""
            if value in ("", sieve_path):
                key = f"sieve_before{n}"
                break
        out["sieve_before_key"] = key
        for name, args in (("sieve_plugins", ("-h", "plugin/sieve_plugins")),
                           ("sieve_global_extensions", ("-h", "plugin/sieve_global_extensions")),
                           ("imap_mail_plugins", ("-h", "-f", "protocol=imap", "mail_plugins"))):
            value = self.doveconf(*args)
            if value is not None:
                out[name] = value.strip().strip('"')
        return out

    def maildir(self, address: str) -> Path:
        local, domain = address.split("@", 1)
        loc = self.detect_mail_location().replace("%d", domain).replace("%n", local)
        return self.root / loc.lstrip("/") if str(self.root) != "/" else Path(loc)


def folder_dir(maildir: Path, folder: str) -> Path:
    """Maildir++ folder path (INBOX is the maildir itself, "A/B" is ".A.B")."""
    if folder.upper() == "INBOX":
        return maildir
    return maildir / ("." + folder.replace("/", "."))
