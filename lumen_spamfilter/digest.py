"""Daily digest: a plain-text list of the messages filed into a mailbox's spam folder.

Only the headers are read (date, sender, subject, Rspamd score). The digest has no links and no
message content, so it cannot carry the phishing it lists. It is sent with sendmail to the
mailbox itself, from digest.from.
"""

from __future__ import annotations

import re
import time
from email import policy
from email.message import EmailMessage
from email.parser import BytesHeaderParser
from email.utils import formatdate, make_msgid, parsedate_to_datetime

from .layout import Layout, folder_dir

CTRL = re.compile(r"[\x00-\x1f\x7f​-‏ -‮⁠﻿]")
SCORE = re.compile(r"score=(-?[0-9]+\.[0-9]+)")


def clean(value: str, width: int) -> str:
    value = CTRL.sub("", " ".join(str(value or "").split()))
    return value if len(value) <= width else value[: width - 1] + "…"


def entries(md_folder, since: float, limit: int) -> list[dict]:
    out = []
    parser = BytesHeaderParser(policy=policy.default)
    for sub in ("new", "cur"):
        d = md_folder / sub
        if not d.is_dir():
            continue
        for p in d.iterdir():
            try:
                if not p.is_file() or p.stat().st_mtime < since:
                    continue
                with p.open("rb") as fh:
                    msg = parser.parse(fh)
            except (OSError, ValueError):
                continue
            try:
                when = parsedate_to_datetime(str(msg.get("Date", ""))).timestamp()
            except (TypeError, ValueError, IndexError):
                when = p.stat().st_mtime
            m = SCORE.search(str(msg.get("X-Spam-Status", "")))
            out.append({"when": when, "from": clean(msg.get("From", ""), 60),
                        "subject": clean(msg.get("Subject", ""), 80), "score": m.group(1) if m else "?"})
    out.sort(key=lambda e: e["when"], reverse=True)
    return out[:limit]


def compose(address: str, sender: str, folder: str, items: list[dict], hours: int = 24) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = address
    msg["Subject"] = f"Spam digest: {len(items)} message(s) in {folder}"
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=sender.split("@", 1)[1])
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-Lumen-Spamfilter"] = "digest"
    lines = [f"Messages filed into \"{folder}\" in the last {hours} hours, newest first.",
             "Open the folder in your mail program to read or rescue one; moving a message",
             "back to the inbox teaches the filter that it is not spam.", ""]
    for e in items:
        stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(e["when"]))
        lines.append(f"{stamp}  score {e['score']:>6}  {e['from']}")
        lines.append(f"    {e['subject']}")
    if not items:
        lines.append("(none)")
    msg.set_content("\n".join(lines) + "\n")
    return msg


def run(cfg: dict, lay: Layout, write: bool, log=print, now: float | None = None) -> int:
    now = now or time.time()
    sent = 0
    for mb in cfg["mailboxes"]:
        if not mb["digest"]:
            continue
        folder = mb["folder"]
        items = entries(folder_dir(lay.maildir(mb["address"]), folder), now - 86400, cfg["digest"]["max_items"])
        if not items:
            log(f"{mb['address']}: nothing new in {folder}, no digest")
            continue
        msg = compose(mb["address"], cfg["digest"]["from"], folder, items)
        if not write:
            log(f"{mb['address']}: would send a digest of {len(items)} message(s)")
            continue
        res = lay.run_input("sendmail", msg.as_bytes(), "-i", "-f", cfg["digest"]["from"], mb["address"])
        if res.returncode == 0:
            sent += 1
            log(f"{mb['address']}: digest of {len(items)} message(s) sent")
        else:
            log(f"{mb['address']}: sendmail failed: {res.stderr.strip()}")
    return sent
