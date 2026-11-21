"""Bayes training: learn spam from the spam folders and ham from the inbox with rspamc.

Idempotent: a SQLite file in the state directory remembers the SHA-256 of every message that
was learned and its class, so a run only sends new messages (and a message that moved from the
inbox to the spam folder is learned again, as spam). Rspamd also refuses to learn the same
message twice, which rspamc reports and this module counts as done.

Only messages are read; nothing is moved, flagged or deleted. Ham is taken only from messages the
user has seen (Maildir flag S) that are at least ham_min_age_days old, so fresh spam that is still
waiting in the inbox is not learned as ham.
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
from pathlib import Path

from .layout import Layout, folder_dir

MAX_BYTES = 10 * 1024 * 1024


def _messages(folder: Path, subdirs: tuple[str, ...]):
    for sub in subdirs:
        d = folder / sub
        if d.is_dir():
            for p in sorted(d.iterdir()):
                if p.is_file() and not p.name.startswith("."):
                    yield p


def _seen(p: Path) -> bool:
    info = p.name.rsplit(":2,", 1)
    return len(info) == 2 and "S" in info[1]


def mailboxes(cfg: dict, lay: Layout) -> list[str]:
    boxes = [m["address"] for m in cfg["mailboxes"]]
    if cfg["training"]["mailboxes"] == "all":
        loc = lay.detect_mail_location()
        base = loc.split("%d", 1)[0]
        root = lay.root / base.lstrip("/") if str(lay.root) != "/" else Path(base)
        if root.is_dir():
            for dom in sorted(p for p in root.iterdir() if p.is_dir()):
                for user in sorted(p for p in dom.iterdir() if p.is_dir()):
                    addr = f"{user.name}@{dom.name}"
                    if addr not in boxes:
                        boxes.append(addr)
    for s in cfg["training"]["spam_mailboxes"]:
        if s not in boxes:
            boxes.append(s)
    return boxes


def candidates(cfg: dict, lay: Layout, now: float | None = None):
    """Yield (class, path) for every message that may be learned."""
    tr = cfg["training"]
    now = now or time.time()
    ham_cutoff = now - tr["ham_min_age_days"] * 86400
    spam_cutoff = now - tr["spam_max_age_days"] * 86400
    for addr in mailboxes(cfg, lay):
        md = lay.maildir(addr)
        if not md.is_dir():
            continue
        if addr in tr["spam_mailboxes"]:
            for p in _messages(md, ("cur", "new")):
                if p.stat().st_mtime >= spam_cutoff:
                    yield "spam", p
            continue
        for folder in tr["spam_folders"]:
            for p in _messages(folder_dir(md, folder), ("cur", "new")):
                if p.stat().st_mtime >= spam_cutoff:
                    yield "spam", p
        for folder in tr["ham_folders"]:
            for p in _messages(folder_dir(md, folder), ("cur",)):
                if _seen(p) and p.stat().st_mtime <= ham_cutoff:
                    yield "ham", p


def open_db(lay: Layout) -> sqlite3.Connection:
    state = lay.path("state_dir")
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(state / "learned.sqlite")
    db.execute("CREATE TABLE IF NOT EXISTS learned (digest TEXT PRIMARY KEY, class TEXT NOT NULL, at INTEGER)")
    return db


def run(cfg: dict, lay: Layout, write: bool, log=print) -> dict:
    stats = {"spam": 0, "ham": 0, "skipped": 0, "failed": 0, "pending": 0}
    if not cfg["training"]["enabled"]:
        log("training is disabled (training.enabled = false)")
        return stats
    db = open_db(lay)
    budget = cfg["training"]["max_per_run"]
    for cls, path in candidates(cfg, lay):
        if budget <= 0:
            break
        try:
            if path.stat().st_size > MAX_BYTES:
                stats["skipped"] += 1
                continue
            data = path.read_bytes()
        except OSError:
            continue  # moved or expunged meanwhile
        digest = hashlib.sha256(data).hexdigest()
        row = db.execute("SELECT class FROM learned WHERE digest = ?", (digest,)).fetchone()
        if row and row[0] == cls:
            stats["skipped"] += 1
            continue
        budget -= 1
        if not write:
            stats["pending"] += 1
            continue
        res = lay.run_input("rspamc", data, "-t", "30", f"learn_{cls}")
        text = (res.stdout + res.stderr).lower()
        if res.returncode == 0 or "already learned" in text or "already been learned" in text:
            db.execute("INSERT OR REPLACE INTO learned VALUES (?, ?, ?)", (digest, cls, int(time.time())))
            db.commit()
            stats[cls] += 1
        else:
            stats["failed"] += 1
            log(f"rspamc learn_{cls} failed for {path.name}: {text.strip()[:200]}")
    db.close()
    return stats
