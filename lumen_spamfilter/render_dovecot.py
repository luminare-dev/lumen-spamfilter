"""Render the Dovecot drop-in (KeyHelp keeps /etc/dovecot/local.conf for the administrator).

It adds one sieve_before script per configured mailbox (a mailbox without a file is skipped by
Pigeonhole) and, when training.imapsieve is on, the IMAPSieve learning hooks.
"""

from __future__ import annotations

from .render_rspamd import header


def _merge(current: str, extra: list[str]) -> str:
    words = current.split()
    return " ".join(words + [w for w in extra if w not in words])


def render(cfg: dict, paths: dict, detected: dict | None = None) -> str:
    """detected: current Dovecot values (sieve_before key, imap mail_plugins, sieve_plugins, ...)."""
    detected = detected or {}
    key = detected.get("sieve_before_key", "sieve_before")
    lines = [header().rstrip("\n"), "", "plugin {",
             f"  # Per-mailbox spam delivery, written by \"lumen-spamfilter apply\".",
             f"  {key} = {paths['sieve_dir']}/%d/%n.sieve"]
    if cfg["training"]["imapsieve"]:
        folder = cfg["training"]["spam_folders"][0]
        plugins = _merge(detected.get("sieve_plugins", ""), ["sieve_imapsieve", "sieve_extprograms"])
        exts = _merge(detected.get("sieve_global_extensions", ""), ["+vnd.dovecot.pipe", "+vnd.dovecot.environment"])
        lines += [
            "",
            "  # Learning hooks: moving mail into the spam folder learns spam, moving it out learns ham.",
            f"  sieve_plugins = {plugins}",
            f"  sieve_global_extensions = {exts}",
            f"  sieve_pipe_bin_dir = {paths['pipe_dir']}",
            f"  imapsieve_mailbox1_name = {folder}",
            "  imapsieve_mailbox1_causes = COPY APPEND",
            f"  imapsieve_mailbox1_before = file:{paths['imapsieve_dir']}/report-spam.sieve",
            "  imapsieve_mailbox2_name = *",
            f"  imapsieve_mailbox2_from = {folder}",
            "  imapsieve_mailbox2_causes = COPY",
            f"  imapsieve_mailbox2_before = file:{paths['imapsieve_dir']}/report-ham.sieve",
        ]
    lines.append("}")
    if cfg["training"]["imapsieve"]:
        current = detected.get("imap_mail_plugins")
        value = _merge(current, ["imap_sieve"]) if current is not None else "$mail_plugins imap_sieve"
        lines += ["", "protocol imap {", f"  mail_plugins = {value}", "}"]
    return "\n".join(lines) + "\n"


def pipe_scripts(paths: dict) -> dict[str, str]:
    """Shell scripts IMAPSieve pipes a message into (read from stdin)."""
    out = {}
    for cls in ("spam", "ham"):
        out[f"lumen-learn-{cls}"] = (
            "#!/bin/sh\n"
            "# lumen-spamfilter: generated file\n"
            f"# Called by Dovecot IMAPSieve with the message on stdin: learn it as {cls}.\n"
            "set -eu\n"
            f"exec {paths['rspamc']} -t 30 learn_{cls}\n")
    return out
