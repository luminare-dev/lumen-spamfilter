"""Command line: lumen-spamfilter check|diff|apply|rollback|render|train|digest|install|uninstall."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, config, deploy, digest, render_dovecot, render_rspamd, render_sieve, train
from .layout import Layout
from .render_rspamd import MARKER

SRC = Path(__file__).resolve().parent.parent
UNITS = ("lumen-spamfilter-train.service", "lumen-spamfilter-train.timer",
         "lumen-spamfilter-digest.service", "lumen-spamfilter-digest.timer")


def _layout(args) -> Layout:
    return Layout(args.root)


def _config(args, lay: Layout) -> dict:
    path = Path(args.config) if args.config else lay.path("config")
    try:
        return config.load(path)
    except FileNotFoundError:
        sys.exit(f"error: configuration file {path} not found (install puts an example there)")
    except config.ConfigError as exc:
        print(f"error: {path} is not valid:", file=sys.stderr)
        for e in exc.errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)


def _print_plan(plan: deploy.Plan) -> None:
    for n in plan.notes:
        print(f"note: {n}")
    print(deploy.summary(plan))
    for c in plan.conflicts:
        print(f"conflict: {c}", file=sys.stderr)


def _finish(ok: bool, log: list[str]) -> int:
    for line in log:
        print(line)
    return 0 if ok else 1


def cmd_check(args) -> int:
    lay = _layout(args)
    cfg = _config(args, lay)
    print(f"configuration ok: {len(cfg['mailboxes'])} mailbox(es), {len(cfg['brands'])} brand(s), "
          f"local domains: {', '.join(cfg['rspamd']['local_domains']) or '(none)'}")
    print("KeyHelp layout: " + ("found" if lay.is_keyhelp() else "not found"))
    plan = deploy.build_plan(cfg, lay, adopt=args.adopt)
    _print_plan(plan)
    ok = not plan.conflicts
    if plan.touches_rspamd:
        good, out = deploy.staged_configtest(lay, plan)
        print("staged rspamadm configtest: " + ("ok" if good else "FAILED"))
        if not good:
            print(out)
        ok = ok and good
    return 0 if ok else 1


def cmd_diff(args) -> int:
    lay = _layout(args)
    plan = deploy.build_plan(_config(args, lay), lay, adopt=args.adopt)
    sys.stdout.write(deploy.diff(plan))
    for c in plan.conflicts:
        print(f"conflict: {c}", file=sys.stderr)
    return 1 if plan.conflicts else 0


def cmd_apply(args) -> int:
    lay = _layout(args)
    plan = deploy.build_plan(_config(args, lay), lay, adopt=args.adopt)
    _print_plan(plan)
    if plan.conflicts:
        return 1
    if not args.write:
        print("dry run: nothing was written. Review with \"lumen-spamfilter diff\", then rerun with --write.")
        return 0
    return _finish(*deploy.apply(plan, lay, "apply"))


def cmd_rollback(args) -> int:
    lay = _layout(args)
    backups = deploy.list_backups(lay)
    if args.list:
        for b in backups:
            print(b.name)
        return 0
    if not backups:
        print("no backups found")
        return 1
    bdir = next((b for b in backups if b.name == args.id), None) if args.id else backups[-1]
    if bdir is None:
        print(f"backup {args.id} not found (see --list)")
        return 1
    plan = deploy.rollback_plan(bdir, lay)
    print(f"rollback to the state before {bdir.name}:")
    _print_plan(plan)
    if not args.write:
        print("dry run: nothing was changed. Rerun with --write.")
        return 0
    return _finish(*deploy.apply(plan, lay, f"rollback of {bdir.name}"))


def cmd_render(args) -> int:
    cfg = config.load(Path(args.config)) if args.config else _config(args, _layout(args))
    out = Path(args.out)
    paths = Layout("/").paths_for_render()
    files = {f"rspamd/{k}": v for k, v in render_rspamd.render(cfg).items()}
    files.update({f"sieve/{k}": v for k, v in render_sieve.render(cfg).items()})
    files["dovecot/local.conf"] = render_dovecot.render(cfg, paths)
    if cfg["training"]["imapsieve"]:
        files.update({f"imapsieve/{k}": v for k, v in render_sieve.imapsieve_scripts().items()})
        files.update({f"sieve-pipe/{k}": v for k, v in render_dovecot.pipe_scripts(paths).items()})
    for rel, text in files.items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    print(f"wrote {len(files)} file(s) to {out}")
    return 0


def cmd_train(args) -> int:
    lay = _layout(args)
    stats = train.run(_config(args, lay), lay, args.write)
    if args.write:
        print(f"learned spam: {stats['spam']}, ham: {stats['ham']}, already known: {stats['skipped']}, "
              f"failed: {stats['failed']}")
    else:
        print(f"dry run: {stats['pending']} message(s) would be learned, {stats['skipped']} already known. "
              "Rerun with --write.")
    return 1 if stats["failed"] else 0


def cmd_digest(args) -> int:
    lay = _layout(args)
    digest.run(_config(args, lay), lay, args.write)
    return 0


# --- install / uninstall --------------------------------------------------------------------

def unit_files(lay: Layout, digest_time: str) -> dict[str, str]:
    bin_link = lay.values["bin_link"]
    state = lay.values["state_dir"]
    head = f"# {MARKER}\n"
    return {
        "lumen-spamfilter-train.service": head + f"""[Unit]
Description=lumen-spamfilter: learn spam and ham for the Rspamd Bayes classifier
After=rspamd.service

[Service]
Type=oneshot
ExecStart={bin_link} train --write
Nice=10
IOSchedulingClass=idle
MemoryMax=256M
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths={state}
""",
        "lumen-spamfilter-train.timer": head + """[Unit]
Description=lumen-spamfilter: daily Bayes training

[Timer]
OnCalendar=*-*-* 03:30
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
""",
        "lumen-spamfilter-digest.service": head + f"""[Unit]
Description=lumen-spamfilter: send the daily spam digests
After=postfix.service

[Service]
Type=oneshot
ExecStart={bin_link} digest --write
Nice=10
MemoryMax=128M
PrivateTmp=yes
ProtectHome=yes
""",
        "lumen-spamfilter-digest.timer": head + f"""[Unit]
Description=lumen-spamfilter: daily spam digest

[Timer]
OnCalendar=*-*-* {digest_time}
Persistent=true

[Install]
WantedBy=timers.target
""",
    }


def install_plan(lay: Layout) -> deploy.Plan:
    plan = deploy.Plan()
    prefix = lay.path("prefix")
    for p in sorted((SRC / "lumen_spamfilter").glob("*.py")):
        plan.changes.append(deploy.Change(prefix / "lumen_spamfilter" / p.name, p.read_text(encoding="utf-8"),
                                          deploy.FILE, deploy._read(prefix / "lumen_spamfilter" / p.name)))
    extras = [("bin/lumen-spamfilter", deploy.EXEC), ("editor/settings.html", deploy.FILE),
              ("examples/config.toml", deploy.FILE)]
    for rel, mode in extras:
        if (SRC / rel).is_file():
            plan.changes.append(deploy.Change(prefix / rel, (SRC / rel).read_text(encoding="utf-8"), mode,
                                              deploy._read(prefix / rel)))
    wrapper = (f"#!/bin/sh\n# {MARKER}\nexec /usr/bin/python3 -I {lay.values['prefix']}/bin/lumen-spamfilter \"$@\"\n")
    deploy._add(plan, lay.path("bin_link"), wrapper, False, deploy.EXEC)
    cfg_path = lay.path("config")
    if not cfg_path.exists() and (SRC / "examples/config.toml").is_file():
        plan.changes.append(deploy.Change(cfg_path, (SRC / "examples/config.toml").read_text(encoding="utf-8"),
                                          0o640, None))
        plan.notes.append(f"{cfg_path}: example configuration; edit it, then run \"lumen-spamfilter check\"")
    digest_time = "07:00"
    if cfg_path.exists():
        try:
            digest_time = config.load(cfg_path)["digest"]["time"]
        except config.ConfigError:
            plan.notes.append(f"{cfg_path} is not valid; the digest timer uses 07:00")
    for name, text in unit_files(lay, digest_time).items():
        deploy._add(plan, lay.path("systemd_dir") / name, text, False)
    return plan


def cmd_install(args) -> int:
    lay = _layout(args)
    if not lay.is_keyhelp() and not args.force:
        print("KeyHelp layout not found (/etc/keyhelp, /etc/dovecot/conf.keyhelp.d). "
              "Use --force to install with the default paths anyway.")
        return 1
    plan = install_plan(lay)
    _print_plan(plan)
    if plan.conflicts:
        return 1
    if not args.write:
        print("dry run: nothing was written. Rerun with --write. Install writes no mail configuration; "
              "\"lumen-spamfilter apply\" does that.")
        return 0
    bdir = deploy.backup(lay, plan.pending, "install")
    deploy.write_changes(plan.pending)
    print(f"backup: {bdir}\ninstalled.")
    lay.run("systemctl", "daemon-reload")
    if args.enable_timers:
        for t in ("lumen-spamfilter-train.timer", "lumen-spamfilter-digest.timer"):
            res = lay.run("systemctl", "enable", "--now", t)
            print(f"enabled {t}" if res.returncode == 0 else f"enable {t} failed: {res.stderr.strip()}")
    return 0


def uninstall_plan(lay: Layout, purge: bool) -> deploy.Plan:
    plan = deploy.Plan()
    conf = lay.path("rspamd_confdir")

    def rm(p: Path, check_marker: bool = True) -> None:
        old = deploy._read(p)
        if old is not None and (not check_marker or deploy.ours(old)):
            plan.changes.append(deploy.Change(p, None, deploy.FILE, old))

    for rel in ("override.d/regexp.conf", "override.d/multimap.conf", "override.d/composites.conf",
                "local.d/groups.conf"):
        rm(conf / rel)
    mapdir = conf / render_rspamd.MAP_DIR
    if mapdir.is_dir():
        for p in sorted(mapdir.iterdir()):
            rm(p)
    rm(lay.path("dovecot_local_conf"))
    for key in ("sieve_dir", "imapsieve_dir"):
        d = lay.path(key)
        if d.is_dir():
            for p in sorted(d.rglob("*")):
                if p.is_file():
                    rm(p, check_marker=p.suffix != ".svbin")
    pdir = lay.path("pipe_dir")
    if pdir.is_dir():
        for p in sorted(pdir.iterdir()):
            rm(p)
    for name in UNITS:
        rm(lay.path("systemd_dir") / name)
    rm(lay.path("bin_link"))
    prefix = lay.path("prefix")
    if prefix.is_dir():
        for p in sorted(prefix.rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts:
                rm(p, check_marker=False)
    if purge:
        rm(lay.path("config"), check_marker=False)
    pend = plan.pending
    plan.touches_rspamd = any(str(c.path).startswith(str(conf)) for c in pend)
    plan.touches_dovecot = lay.path("dovecot_local_conf") in [c.path for c in pend]
    return plan


def cmd_uninstall(args) -> int:
    lay = _layout(args)
    plan = uninstall_plan(lay, args.purge)
    _print_plan(plan)
    if not args.write:
        print("dry run: nothing was removed. Rerun with --write. Backups in "
              f"{lay.path('backup_dir')} are kept" + ("" if args.purge else ", and so is the configuration file") + ".")
        return 0
    for t in ("lumen-spamfilter-train.timer", "lumen-spamfilter-digest.timer"):
        lay.run("systemctl", "disable", "--now", t)
    ok, log = deploy.apply(plan, lay, "uninstall")
    lay.run("systemctl", "daemon-reload")
    return _finish(ok, log)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="lumen-spamfilter", description=__doc__)
    ap.add_argument("--version", action="version", version=f"lumen-spamfilter {__version__}")
    ap.add_argument("--config", help="configuration file (default /etc/lumen-spamfilter/config.toml)")
    ap.add_argument("--root", default=os.environ.get("LUMEN_SPAMFILTER_ROOT", "/"), help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name, func, help_text, write=True, adopt=False):
        p = sub.add_parser(name, help=help_text)
        if write:
            p.add_argument("--write", action="store_true", help="really change files (default: dry run)")
        if adopt:
            p.add_argument("--adopt", action="store_true",
                           help="replace existing files that lumen-spamfilter did not write (after a backup)")
        p.set_defaults(func=func)
        return p

    add("check", cmd_check, "validate the configuration and test the generated files", write=False, adopt=True)
    add("diff", cmd_diff, "show what apply would change", write=False, adopt=True)
    add("apply", cmd_apply, "write the Rspamd and Sieve files, test and reload", adopt=True)
    p = add("rollback", cmd_rollback, "restore the files from a backup")
    p.add_argument("id", nargs="?", help="backup name (default: the newest)")
    p.add_argument("--list", action="store_true", help="list the backups")
    p = add("render", cmd_render, "write the generated files into a folder", write=False)
    p.add_argument("--out", required=True)
    add("train", cmd_train, "learn spam and ham with rspamc")
    add("digest", cmd_digest, "send the daily spam digests")
    p = add("install", cmd_install, "install the program, the example configuration and the timers")
    p.add_argument("--enable-timers", action="store_true", help="also enable the training and digest timers")
    p.add_argument("--force", action="store_true", help="install even without the KeyHelp layout")
    p = add("uninstall", cmd_uninstall, "remove everything lumen-spamfilter wrote, then reload")
    p.add_argument("--purge", action="store_true", help="also remove the configuration file")
    args = ap.parse_args(argv)
    if getattr(args, "adopt", None) is None:
        args.adopt = False
    return args.func(args)
