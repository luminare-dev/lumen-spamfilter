"""Plan, apply, back up and roll back the generated files.

Rules: every changing command is a dry run unless --write is given; every file that is written
or removed is backed up first (a file that did not exist is recorded as absent, so a rollback
removes it again); a file without the lumen-spamfilter marker is never replaced unless --adopt
is given; Rspamd's configtest must pass on a staged copy before anything is written, and again
on the live tree before Rspamd is reloaded.
"""

from __future__ import annotations

import difflib
import json
import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import render_dovecot, render_rspamd, render_sieve
from .layout import Layout
from .render_rspamd import MARKER

EXEC = 0o755
FILE = 0o644


@dataclass
class Change:
    path: Path
    content: str | None          # None: remove the file
    mode: int = FILE
    old: str | None = None       # current content (None: absent)

    @property
    def kind(self) -> str:
        if self.content is None:
            return "remove"
        return "create" if self.old is None else ("update" if self.old != self.content else "same")


@dataclass
class Plan:
    changes: list[Change] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    sieve_files: list[Path] = field(default_factory=list)
    touches_rspamd: bool = False
    touches_dovecot: bool = False

    @property
    def pending(self) -> list[Change]:
        return [c for c in self.changes if c.kind != "same"]


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except UnicodeDecodeError:
        return "\0binary"


def ours(text: str | None) -> bool:
    return text is not None and MARKER in text[:400]


def _add(plan: Plan, path: Path, content: str | None, adopt: bool, mode: int = FILE) -> None:
    old = _read(path)
    if content is not None and old is not None and not ours(old) and not adopt:
        plan.conflicts.append(f"{path}: exists and was not written by lumen-spamfilter (back it up and "
                              "merge it by hand, or rerun with --adopt to replace it after a backup)")
        return
    plan.changes.append(Change(path, content, mode, old))


def _stale(plan: Plan, directory: Path, keep: set[Path], suffix: str) -> None:
    if not directory.is_dir():
        return
    for p in sorted(directory.rglob(f"*{suffix}")):
        if p not in keep and ours(_read(p)):
            plan.changes.append(Change(p, None, FILE, _read(p)))
            if suffix == ".sieve":
                svbin = p.with_suffix(".svbin")
                if svbin.exists():
                    plan.changes.append(Change(svbin, None, FILE, "\0binary"))


def build_plan(cfg: dict, lay: Layout, adopt: bool = False) -> Plan:
    plan = Plan()
    paths = lay.paths_for_render()
    if not lay.is_keyhelp():
        plan.notes.append("KeyHelp layout not found (/etc/keyhelp, /etc/dovecot/conf.keyhelp.d); "
                          "using the default paths anyway")
    conf = lay.path("rspamd_confdir")
    rspamd_files = render_rspamd.render(cfg)
    for rel, text in rspamd_files.items():
        _add(plan, conf / rel, text, adopt)
    _stale(plan, conf / render_rspamd.MAP_DIR, {conf / r for r in rspamd_files}, ".map")

    sieve_path = f"{paths['sieve_dir']}/%d/%n.sieve"
    detected = lay.detect_dovecot(sieve_path)
    _add(plan, lay.path("dovecot_local_conf"), render_dovecot.render(cfg, paths, detected), adopt)

    sdir = lay.path("sieve_dir")
    keep = set()
    for rel, text in render_sieve.render(cfg).items():
        p = sdir / rel
        keep.add(p)
        plan.sieve_files.append(p)
        _add(plan, p, text, adopt)
    _stale(plan, sdir, keep, ".sieve")

    idir, pdir = lay.path("imapsieve_dir"), lay.path("pipe_dir")
    if cfg["training"]["imapsieve"]:
        for name, text in render_sieve.imapsieve_scripts().items():
            plan.sieve_files.append(idir / name)
            _add(plan, idir / name, text, adopt)
        for name, text in render_dovecot.pipe_scripts(paths).items():
            _add(plan, pdir / name, text, adopt, EXEC)
    else:
        _stale(plan, idir, set(), ".sieve")
        for name in render_dovecot.pipe_scripts(paths):
            if ours(_read(pdir / name)):
                plan.changes.append(Change(pdir / name, None, EXEC, _read(pdir / name)))

    pend = plan.pending
    plan.touches_rspamd = any(str(c.path).startswith(str(conf)) for c in pend)
    plan.touches_dovecot = any(not str(c.path).startswith(str(conf)) for c in pend)
    if cfg["mailboxes"] == []:
        plan.notes.append("no [[mailbox]] configured: Rspamd rules only, no Sieve delivery policy")
    return plan


def diff(plan: Plan) -> str:
    out = []
    for c in plan.pending:
        if "\0binary" in (c.old or "") or (c.content and "\0" in c.content):
            out.append(f"binary file {c.path} ({c.kind})\n")
            continue
        a = (c.old or "").splitlines(keepends=True)
        b = (c.content or "").splitlines(keepends=True)
        out.extend(difflib.unified_diff(a, b, f"a{c.path}" if c.old is not None else "/dev/null",
                                        f"b{c.path}" if c.content is not None else "/dev/null"))
    return "".join(out)


def summary(plan: Plan) -> str:
    lines = [f"  {c.kind:7} {c.path}" for c in plan.pending]
    unchanged = len(plan.changes) - len(plan.pending)
    if unchanged:
        lines.append(f"  ({unchanged} file(s) already up to date)")
    return "\n".join(lines) if lines else "  nothing to change"


# --- checks ---------------------------------------------------------------------------------

def staged_configtest(lay: Layout, plan: Plan) -> tuple[bool, str]:
    """Run rspamadm configtest on a copy of the live local.d/override.d with the plan applied."""
    conf = lay.path("rspamd_confdir")
    with tempfile.TemporaryDirectory(prefix="lumen-spamfilter-") as tmp:
        stage = Path(tmp)
        for sub in ("local.d", "override.d"):
            if (conf / sub).is_dir():
                shutil.copytree(conf / sub, stage / sub, symlinks=True)
        for c in plan.changes:
            if not str(c.path).startswith(str(conf) + os.sep):
                continue
            target = stage / c.path.relative_to(conf)
            if c.content is None:
                target.unlink(missing_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(c.content, encoding="utf-8")
        try:
            res = lay.run("rspamadm", f"--var=LOCAL_CONFDIR={stage}", "configtest")
        except OSError as exc:
            return False, f"rspamadm not found: {exc}"
        text = "\n".join(l for l in (res.stdout + res.stderr).splitlines() if "has no score registered" not in l)
        return res.returncode == 0, text.strip()


def live_checks(lay: Layout, plan: Plan) -> list[str]:
    errors = []
    if plan.touches_rspamd:
        res = lay.run("rspamadm", "configtest")
        if res.returncode != 0:
            errors.append("rspamadm configtest failed:\n" + (res.stdout + res.stderr).strip())
    if plan.touches_dovecot:
        res = lay.run("doveconf", "-n")
        if res.returncode != 0:
            errors.append("doveconf -n failed:\n" + res.stderr.strip())
        for p in plan.sieve_files:
            res = lay.run("sievec", str(p))
            if res.returncode != 0:
                errors.append(f"sievec {p} failed:\n" + (res.stdout + res.stderr).strip())
    return errors


# --- backups --------------------------------------------------------------------------------

def backup(lay: Layout, changes: list[Change], label: str) -> Path:
    base = lay.path("backup_dir")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    bdir = base / stamp
    n = 1
    while bdir.exists():
        n += 1
        bdir = base / f"{stamp}-{n}"
    (bdir / "files").mkdir(parents=True, mode=0o700)
    os.chmod(base, 0o700)
    entries = []
    for c in changes:
        entry = {"path": str(c.path), "existed": c.path.exists()}
        if entry["existed"]:
            st = c.path.stat()
            entry["mode"] = st.st_mode & 0o7777
            dest = bdir / "files" / str(c.path).lstrip("/")
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(c.path, dest)
        entries.append(entry)
    (bdir / "manifest.json").write_text(json.dumps({"label": label, "created": stamp, "files": entries},
                                                   indent=2) + "\n", encoding="utf-8")
    return bdir


def list_backups(lay: Layout) -> list[Path]:
    base = lay.path("backup_dir")
    if not base.is_dir():
        return []
    return sorted(p for p in base.iterdir() if (p / "manifest.json").is_file())


def restore(bdir: Path) -> list[str]:
    manifest = json.loads((bdir / "manifest.json").read_text(encoding="utf-8"))
    done = []
    for e in manifest["files"]:
        p = Path(e["path"])
        if e["existed"]:
            p.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(bdir / "files" / e["path"].lstrip("/"), p)
            os.chmod(p, e.get("mode", FILE))
            done.append(f"restored {p}")
        elif p.exists():
            p.unlink()
            done.append(f"removed  {p}")
    return done


def write_changes(changes: list[Change]) -> None:
    for c in changes:
        if c.kind == "same":
            continue
        if c.content is None:
            c.path.unlink(missing_ok=True)
            continue
        c.path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        tmp = c.path.with_name(f".{c.path.name}.lumen-tmp")
        tmp.write_text(c.content, encoding="utf-8")
        os.chmod(tmp, c.mode)
        os.replace(tmp, c.path)


def reload(lay: Layout, plan: Plan) -> list[str]:
    msgs = []
    for unit, needed in (("rspamd", plan.touches_rspamd), ("dovecot", plan.touches_dovecot)):
        if not needed:
            continue
        res = lay.run("systemctl", "reload", unit)
        msgs.append(f"reloaded {unit}" if res.returncode == 0 else f"reload {unit} failed: {res.stderr.strip()}")
    return msgs


def apply(plan: Plan, lay: Layout, label: str = "apply") -> tuple[bool, list[str]]:
    """Write a checked plan: staged configtest, backup, write, live checks (or restore), reload."""
    log: list[str] = []
    pend = plan.pending
    if not pend:
        return True, ["nothing to change"]
    if plan.touches_rspamd:
        ok, out = staged_configtest(lay, plan)
        if not ok:
            return False, ["staged rspamadm configtest failed, nothing was written:", out]
        log.append("staged rspamadm configtest: ok")
    bdir = backup(lay, pend, label)
    log.append(f"backup: {bdir}")
    write_changes(pend)
    errors = live_checks(lay, plan)
    if errors:
        log += errors
        log += restore(bdir)
        log.append("the previous files were restored; services were not reloaded")
        return False, log
    log += reload(lay, plan)
    return True, log


def rollback_plan(bdir: Path, lay: Layout) -> Plan:
    manifest = json.loads((bdir / "manifest.json").read_text(encoding="utf-8"))
    plan = Plan()
    conf = str(lay.path("rspamd_confdir"))
    for e in manifest["files"]:
        p = Path(e["path"])
        content = None
        if e["existed"]:
            content = _read(bdir / "files" / e["path"].lstrip("/"))
            if content == "\0binary":
                continue  # compiled Sieve binaries: sievec writes them again
        current = _read(p)
        if content is None and current is not None and not ours(current) and not p.suffix == ".svbin":
            plan.notes.append(f"{p}: kept (created after the backup, not by lumen-spamfilter)")
            continue
        plan.changes.append(Change(p, content, e.get("mode", FILE), current))
        if p.suffix == ".sieve" and content is not None:
            plan.sieve_files.append(p)
    pend = plan.pending
    plan.touches_rspamd = any(str(c.path).startswith(conf) for c in pend)
    plan.touches_dovecot = any(not str(c.path).startswith(conf) for c in pend)
    return plan
