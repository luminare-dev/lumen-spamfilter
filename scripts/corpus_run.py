#!/usr/bin/env python3
"""Scan the synthetic corpus with a real Rspamd (official container image) and check the results.

What it does (CI job "corpus"; needs docker and openssl, nothing else):
  1. renders the rules from tests/corpus/config.toml into override.d/, plus a DNS setting that
     points Rspamd at scripts/corpus_dns.py;
  2. creates a throwaway DKIM key and a zone with SPF, DKIM, DMARC, MX, A and PTR records for every
     synthetic sender, so the spam samples authenticate like spam from throwaway domains does
     (valid DKIM, SPF pass, DMARC pass: the stock score goes negative);
  3. starts the pinned Rspamd image with host networking and scans every message with rspamc,
     twice: with the configured group limit (checks action and score as on a server) and without
     it and with --pass-all (checks that every expected rule matches; the limit drops rules once
     it is reached, and Rspamd stops checking once a message reaches the reject score);
  4. compares the results with tests/corpus/corpus.toml and prints a table
     (and a job summary on GitHub).

Usage: python3 scripts/corpus_run.py [--image IMAGE] [--work DIR] [--keep]
Exit codes: 0 all expectations met, 1 a message failed, 2 setup error.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import tomllib
from email.utils import formatdate
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lumen_spamfilter import config, render_rspamd  # noqa: E402

CORPUS = ROOT / "tests" / "corpus"
IMAGE = "rspamd/rspamd:4.3.0@sha256:0d89891908f93ab1ce53c17fa90430130b48ad720216192ec44e646997c0a8e1"
CONTAINER = "lumen-spamfilter-corpus"
DNS_PORT = 5353
SELECTOR = "lumen"
SIGNED = ["from", "to", "subject", "date", "message-id", "mime-version", "content-type"]


def sh(*cmd: str, data: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(list(cmd), input=data, capture_output=True, check=check)


# --- DKIM signing (relaxed/relaxed, rsa-sha256, RFC 6376) -------------------------------------

def split_message(raw: bytes) -> tuple[list[bytes], bytes]:
    head, _, body = raw.partition(b"\r\n\r\n")
    headers: list[bytes] = []
    for line in head.split(b"\r\n"):
        if line[:1] in (b" ", b"\t") and headers:
            headers[-1] += b"\r\n" + line
        else:
            headers.append(line)
    return headers, body


def relaxed_header(h: bytes) -> bytes:
    name, _, value = h.partition(b":")
    value = re.sub(rb"\r\n", b"", value)
    value = re.sub(rb"[ \t]+", b" ", value).strip()
    return name.strip().lower() + b":" + value


def relaxed_body(body: bytes) -> bytes:
    lines = [re.sub(rb"[ \t]+", b" ", line).rstrip(b" ") for line in body.split(b"\r\n")]
    while lines and lines[-1] == b"":
        lines.pop()
    return b"".join(line + b"\r\n" for line in lines)


def dkim_sign(raw: bytes, domain: str, key: Path) -> bytes:
    headers, body = split_message(raw)
    bh = base64.b64encode(hashlib.sha256(relaxed_body(body)).digest()).decode()
    by_name = {}
    for h in headers:
        by_name.setdefault(h.split(b":", 1)[0].strip().lower().decode(), h)
    names = [n for n in SIGNED if n in by_name]
    sig = (f"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d={domain}; s={SELECTOR};"
           f" t={int(time.time())}; h={':'.join(names)}; bh={bh}; b=")
    data = b"".join(relaxed_header(by_name[n]) + b"\r\n" for n in names) + relaxed_header(sig.encode())
    signature = sh("openssl", "dgst", "-sha256", "-sign", str(key), data=data).stdout
    return (sig + base64.b64encode(signature).decode()).encode() + b"\r\n" + raw


# --- corpus -----------------------------------------------------------------------------------

def from_address(raw: bytes) -> str:
    m = re.search(rb"^From:.*?<([^>]+)>", raw, re.M | re.I) or re.search(rb"^From:\s*(\S+@\S+)", raw, re.M | re.I)
    if not m:
        raise SystemExit("a corpus message has no From address")
    return m.group(1).decode().lower()


def prepare(entries: list[dict]) -> list[dict]:
    out = []
    for i, e in enumerate(entries):
        raw = (CORPUS / e["file"]).read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        sender = from_address(raw)
        domain = sender.split("@", 1)[1]
        ip = e.get("spf_ip", f"198.51.100.{10 + i}")
        helo = f"mail{i}.{domain}" if ip.startswith("198.51.100.") else "relay.attacker.invalid"
        rcpt = e.get("rcpt", "user@example.com")
        out.append({**e, "raw": raw, "sender": sender, "domain": domain, "ip": ip, "helo": helo, "rcpt": rcpt})
    return out


def zone_for(msgs: list[dict], pubkey: str) -> dict:
    zone: dict[str, dict] = {}

    def add(name: str, rtype: str, value: str) -> None:
        values = zone.setdefault(name.lower(), {}).setdefault(rtype, [])
        if value not in values:
            values.append(value)

    for m in msgs:
        d = m["domain"]
        add(d, "TXT", "v=spf1 ip4:198.51.100.0/24 -all")
        add(d, "MX", f"mx.{d}")
        add(d, "A", "198.51.100.200")
        add(f"mx.{d}", "A", "198.51.100.200")
        add(f"{SELECTOR}._domainkey.{d}", "TXT", f"v=DKIM1; k=rsa; p={pubkey}")
        policy = m.get("dmarc", "none")
        dm = zone.setdefault(f"_dmarc.{d}", {}).setdefault("TXT", [])
        if not dm or policy == "reject":
            dm[:] = [f"v=DMARC1; p={policy}"]
        add(m["helo"], "A", m["ip"])
        rev = ".".join(reversed(m["ip"].split("."))) + ".in-addr.arpa"
        add(rev, "PTR", m["helo"])
    add("example.com", "A", "198.51.100.201")
    return zone


def add_trace(m: dict) -> bytes:
    stamp = formatdate(localtime=False)
    mid = hashlib.sha256(m["raw"]).hexdigest()[:16]
    trace = (f"Received: from {m['helo']} ({m['helo']} [{m['ip']}])\r\n"
             f"\tby mx.example.com with ESMTPS id {mid.upper()[:10]}\r\n"
             f"\tfor <{m['rcpt']}>; {stamp}\r\n"
             f"Date: {stamp}\r\nMessage-ID: <{mid}@{m['domain']}>\r\n").encode()
    return trace + m["raw"]


# --- run --------------------------------------------------------------------------------------

def check(m: dict, res: dict, mode: str) -> list[str]:
    """mode "action": the action and score; mode "rules": which rules matched."""
    errors = []
    score = res.get("score", 0.0)
    action = res.get("action", "?")
    syms = set(res.get("symbols", {}))
    if mode == "action":
        if m["expect"] == "spam" and score < 6:
            errors.append(f"expected spam (score >= 6), got {score:.2f} ({action})")
        if m["expect"] == "ham" and action != "no action":
            errors.append(f"expected ham (no action, score < 4), got {score:.2f} ({action})")
        return errors
    for s in m.get("symbols", []):
        if s not in syms:
            errors.append(f"missing {s}")
    for s in m.get("not_symbols", []):
        if s in syms:
            errors.append(f"unexpected {s}")
    return errors


def render_into(rs: Path, cfg: dict) -> None:
    for rel, text in render_rspamd.render(cfg).items():
        p = rs / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    (rs / "override.d" / "options.inc").write_text(
        "# corpus test only: resolve everything with scripts/corpus_dns.py\n"
        f'dns {{\n  nameserver = ["127.0.0.1:{DNS_PORT}"];\n  timeout = 1s;\n  retransmits = 2;\n}}\n',
        encoding="utf-8")
    for p in [rs, *rs.rglob("*")]:
        os.chmod(p, 0o755 if p.is_dir() else 0o644)


def scan(image: str, rs: Path, msgs: list[dict], key: Path, keep: bool, pass_all: bool = False) -> list[dict]:
    sh("docker", "rm", "-f", CONTAINER, check=False)
    mounts = ["-v", f"{rs / 'override.d'}:/etc/rspamd/override.d:ro",
              "-v", f"{rs / 'local.d' / 'groups.conf'}:/etc/rspamd/local.d/groups.conf:ro"]
    sh("docker", "run", "-d", "--name", CONTAINER, "--network", "host", *mounts, image)
    try:
        deadline = time.time() + 180
        while sh("docker", "exec", CONTAINER, "rspamc", "-t", "5", "stat", check=False).returncode != 0:
            if time.time() > deadline:
                print(sh("docker", "logs", CONTAINER, check=False).stderr.decode()[-4000:])
                raise SystemExit("Rspamd did not start")
            time.sleep(2)
        out_list = []
        for m in msgs:
            raw = add_trace(m)
            if m.get("dkim", True):
                raw = dkim_sign(raw, m["domain"], key)
            extra = ["--pass-all"] if pass_all else []
            out = sh("docker", "exec", "-i", CONTAINER, "rspamc", "-j", "-t", "60", *extra, "--ip", m["ip"],
                     "--helo", m["helo"], "--hostname", m["helo"], "--from", m["sender"], "--rcpt", m["rcpt"],
                     data=raw, check=False)
            try:
                out_list.append(json.loads(out.stdout.decode()))
            except json.JSONDecodeError:
                out_list.append({"error": (out.stdout + out.stderr).decode()[:500]})
        logs = sh("docker", "logs", CONTAINER, check=False).stderr.decode()
        bad = [l for l in logs.splitlines() if "lumen" in l.lower() and ("error" in l.lower() or "cannot" in l.lower())]
        if bad:
            print("rspamd reported problems with the lumen rules:\n" + "\n".join(bad[-20:]))
        return out_list
    finally:
        if not keep:
            sh("docker", "rm", "-f", CONTAINER, check=False)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--image", default=IMAGE)
    ap.add_argument("--work", help="work folder (default: a temporary one)")
    ap.add_argument("--keep", action="store_true", help="leave the container running")
    ap.add_argument("--json", help="write the raw results here")
    args = ap.parse_args(argv)

    work = Path(args.work or tempfile.mkdtemp(prefix="lumen-corpus-"))
    work.mkdir(parents=True, exist_ok=True)
    os.chmod(work, 0o755)
    cfg = config.load(CORPUS / "config.toml")
    uncapped = config.load(CORPUS / "config.toml")
    uncapped["rspamd"]["group_max_score"] = 100.0

    key = work / "dkim.key"
    sh("openssl", "genrsa", "-out", str(key), "1024")
    der = sh("openssl", "rsa", "-in", str(key), "-pubout", "-outform", "DER").stdout
    msgs = prepare(tomllib.loads((CORPUS / "corpus.toml").read_text(encoding="utf-8"))["message"])
    (work / "zone.json").write_text(json.dumps(zone_for(msgs, base64.b64encode(der).decode()), indent=1),
                                    encoding="utf-8")
    dns = subprocess.Popen([sys.executable, str(ROOT / "scripts" / "corpus_dns.py"), str(work / "zone.json"),
                            "--port", str(DNS_PORT)])
    try:
        render_into(work / "rspamd-default", cfg)
        render_into(work / "rspamd-uncapped", uncapped)
        real = scan(args.image, work / "rspamd-default", msgs, key, False)
        rules = scan(args.image, work / "rspamd-uncapped", msgs, key, args.keep, pass_all=True)
    finally:
        dns.terminate()

    results, rows = [], ["| message | expect | action | score | lumen rules (uncapped run) | result |",
                         "|---|---|---|---|---|---|"]
    for m, res, res_u in zip(msgs, real, rules):
        errors = [res["error"]] if "error" in res else check(m, res, "action")
        errors += [res_u["error"]] if "error" in res_u else check(m, res_u, "rules")
        lumen = sorted(s for s in res_u.get("symbols", {}) if s.startswith("LUMEN_"))
        results.append({"file": m["file"], "expect": m["expect"], "action": res.get("action"),
                        "score": res.get("score"), "symbols": res.get("symbols", {}),
                        "uncapped_score": res_u.get("score"), "uncapped_symbols": sorted(res_u.get("symbols", {})),
                        "errors": errors})
        rows.append(f"| {m['file']} | {m['expect']} | {res.get('action')} | {res.get('score', 0):.2f} | "
                    f"{', '.join(lumen)} | {'ok' if not errors else 'FAIL: ' + '; '.join(errors)} |")
    spam = [r for r in results if r["expect"] == "spam"]
    ham = [r for r in results if r["expect"] == "ham"]
    summary = (f"spam: {sum(not r['errors'] for r in spam)}/{len(spam)} passed, "
               f"ham: {sum(not r['errors'] for r in ham)}/{len(ham)} passed")
    version = args.image.split("@")[0].split(":")[-1]
    report = "\n".join([f"## Corpus scan (Rspamd {version})", "", summary, ""] + rows) + "\n"
    print(report)
    for r in results:
        if r["errors"]:
            detail = ", ".join(f"{k}={v.get('score', 0):.2f}" for k, v in sorted(r["symbols"].items()))
            print(f"{r['file']}: {detail}\n")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(report)
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=1), encoding="utf-8")
    return 1 if any(r["errors"] for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
