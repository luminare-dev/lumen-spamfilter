"""Load and validate the configuration file (TOML) into one normalised dictionary.

The editor page implements the same normalisation in JavaScript; tests/test_editor_parity.py
checks that both produce the same Rspamd and Sieve files.
"""

from __future__ import annotations

import copy
import re
import tomllib
from pathlib import Path

from . import catalog, defaults

ADDRESS_RE = re.compile(r"^[A-Za-z0-9._%+=-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
TLD_RE = re.compile(r"^[a-z0-9-]{2,63}$")
FOLDER_RE = re.compile(r"^[A-Za-z0-9 _.\-/äöüÄÖÜß]{1,100}$")
TIME_RE = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
SYMBOL_RE = re.compile(r"^LUMEN_[A-Z0-9_]+$")
ACTIONS = ("junk", "redirect", "keep")

TOP_KEYS = {"version", "rspamd", "scores", "terms", "brands", "tlds", "allow", "block", "delivery", "mailbox",
            "training", "digest"}


class ConfigError(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("\n".join(errors))
        self.errors = errors


def _list(errors: list[str], where: str, value, kind: str = "string") -> list:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        errors.append(f"{where}: must be a list of {kind}s")
        return []
    return [v.strip() for v in value if v.strip()]


def _number(errors: list[str], where: str, value, lo: float, hi: float, default: float) -> float:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        errors.append(f"{where}: must be a number")
        return default
    if not lo <= float(value) <= hi:
        errors.append(f"{where}: must be between {lo:g} and {hi:g}")
        return default
    return round(float(value), 2)


def _bool(errors: list[str], where: str, value, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        errors.append(f"{where}: must be true or false")
        return default
    return value


def _unknown(errors: list[str], where: str, table: dict, allowed: set[str]) -> None:
    for key in sorted(set(table) - allowed):
        errors.append(f"{where}.{key}: unknown setting" if where else f"{key}: unknown setting")


def _table(errors: list[str], raw: dict, key: str) -> dict:
    value = raw.get(key, {})
    if not isinstance(value, dict):
        errors.append(f"{key}: must be a table")
        return {}
    return value


def _domains(errors: list[str], where: str, value) -> list[str]:
    out = []
    for d in _list(errors, where, value, "domain"):
        d = d.lower().rstrip(".")
        if not DOMAIN_RE.match(d):
            errors.append(f"{where}: {d!r} is not a domain name")
        elif d not in out:
            out.append(d)
    return out


def _senders(errors: list[str], where: str, value) -> list[str]:
    """Addresses or domains (an entry without "@" is a domain)."""
    out = []
    for s in _list(errors, where, value, "address or domain"):
        s = s.lower()
        ok = ADDRESS_RE.match(s) if "@" in s else DOMAIN_RE.match(s)
        if not ok:
            errors.append(f"{where}: {s!r} is not an address or domain")
        elif s not in out:
            out.append(s)
    return out


def _threshold(errors: list[str], where: str, value, default):
    if value is None:
        return default
    if value == "action":
        return "action"
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        errors.append(f"{where}: must be \"action\" or a score such as 4.5")
        return default
    if not 0 < float(value) <= 100:
        errors.append(f"{where}: must be above 0 and at most 100")
        return default
    return round(float(value), 2)


def _policy(errors: list[str], where: str, table: dict, base: dict) -> dict:
    pol = dict(base)
    if "action" in table:
        if table["action"] not in ACTIONS:
            errors.append(f"{where}.action: must be one of {', '.join(ACTIONS)}")
        else:
            pol["action"] = table["action"]
    if "folder" in table:
        folder = table["folder"]
        if not isinstance(folder, str) or not FOLDER_RE.match(folder) or ".." in folder or folder.startswith(("/", ".")):
            errors.append(f"{where}.folder: letters, digits, spaces and _ . - / only (no leading dot or slash)")
        else:
            pol["folder"] = folder
    pol["threshold"] = _threshold(errors, f"{where}.threshold", table.get("threshold"), pol["threshold"])
    pol["digest"] = _bool(errors, f"{where}.digest", table.get("digest"), pol["digest"])
    pol["keep_copy"] = _bool(errors, f"{where}.keep_copy", table.get("keep_copy"), pol["keep_copy"])
    if "redirect_to" in table:
        rt = table["redirect_to"]
        if not isinstance(rt, str) or not ADDRESS_RE.match(rt.strip()):
            errors.append(f"{where}.redirect_to: must be an e-mail address")
        else:
            pol["redirect_to"] = rt.strip().lower()
    return pol


def normalise(raw: dict) -> dict:
    """Validate raw (parsed TOML) and return the normalised configuration; raise ConfigError."""
    errors: list[str] = []
    if not isinstance(raw, dict):
        raise ConfigError(["the configuration must be a TOML table"])
    _unknown(errors, "", raw, TOP_KEYS)
    version = raw.get("version", 1)
    if version != 1:
        errors.append("version: only version 1 is supported")

    rs = _table(errors, raw, "rspamd")
    _unknown(errors, "rspamd", rs, {"local_domains", "group_max_score", "add_header_score", "default_brands"})
    rspamd = {
        "local_domains": _domains(errors, "rspamd.local_domains", rs.get("local_domains")),
        "group_max_score": _number(errors, "rspamd.group_max_score", rs.get("group_max_score"), 1, 100, 12.0),
        "add_header_score": _number(errors, "rspamd.add_header_score", rs.get("add_header_score"), 0.1, 100, 6.0),
        "default_brands": _bool(errors, "rspamd.default_brands", rs.get("default_brands"), True),
    }

    sc = _table(errors, raw, "scores")
    scores = {r["symbol"]: r["score"] for r in catalog.RULES}
    for sym, val in sc.items():
        if sym not in catalog.BY_SYMBOL:
            errors.append(f"scores.{sym}: unknown symbol (see docs/rules.md)")
            continue
        scores[sym] = _number(errors, f"scores.{sym}", val, -50, 50, scores[sym])

    tm = _table(errors, raw, "terms")
    _unknown(errors, "terms", tm, {"strong", "weak", "subject", "replace_defaults"})
    replace = _bool(errors, "terms.replace_defaults", tm.get("replace_defaults"), False)
    terms = {}
    for key, base in (("strong", defaults.PHARMA_STRONG), ("weak", defaults.PHARMA_WEAK),
                      ("subject", defaults.PHARMA_SUBJECT)):
        extra = [t.lower() for t in _list(errors, f"terms.{key}", tm.get(key), "word")]
        for t in extra:
            if len(t) < 3 or len(t) > 60 or not re.match(r"^[a-zäöüß0-9][a-zäöüß0-9 \-]*$", t):
                errors.append(f"terms.{key}: {t!r} must be 3-60 letters, digits, spaces or hyphens")
        merged = [] if replace else list(base)
        terms[key] = merged + [t for t in extra if t not in merged]

    brands = copy.deepcopy(defaults.BRANDS) if rspamd["default_brands"] else []
    raw_brands = raw.get("brands", [])
    if not isinstance(raw_brands, list):
        errors.append("brands: must be an array of tables ([[brands]])")
        raw_brands = []
    for i, b in enumerate(raw_brands):
        where = f"brands[{i}]"
        if not isinstance(b, dict):
            errors.append(f"{where}: must be a table")
            continue
        _unknown(errors, where, b, {"name", "domains", "url_tokens"})
        name = b.get("name")
        if not isinstance(name, str) or not 2 <= len(name.strip()) <= 60:
            errors.append(f"{where}.name: must be a name of 2-60 characters")
            continue
        doms = _domains(errors, f"{where}.domains", b.get("domains"))
        if not doms:
            errors.append(f"{where}.domains: list at least one domain the brand sends from")
        tokens = [t.lower() for t in _list(errors, f"{where}.url_tokens", b.get("url_tokens"))]
        for t in tokens:
            if not re.match(r"^[a-z0-9][a-z0-9-]{3,40}$", t):
                errors.append(f"{where}.url_tokens: {t!r} must be 4-41 letters, digits or hyphens")
        existing = next((x for x in brands if x["name"].lower() == name.strip().lower()), None)
        if existing:
            existing["domains"] = sorted(set(existing["domains"]) | set(doms))
            existing["url_tokens"] = sorted(set(existing["url_tokens"]) | set(tokens))
        else:
            brands.append({"name": name.strip(), "domains": doms, "url_tokens": tokens})

    tl = _table(errors, raw, "tlds")
    _unknown(errors, "tlds", tl, {"extra_high", "extra_medium", "remove"})
    remove = {t.lower().lstrip(".") for t in _list(errors, "tlds.remove", tl.get("remove"))}
    tlds = {}
    for key, base in (("high", defaults.TLDS_HIGH), ("medium", defaults.TLDS_MEDIUM)):
        extra = [t.lower().lstrip(".") for t in _list(errors, f"tlds.extra_{key}", tl.get(f"extra_{key}"))]
        for t in extra:
            if not TLD_RE.match(t):
                errors.append(f"tlds.extra_{key}: {t!r} is not a top-level domain")
        merged = [t for t in base if t not in remove]
        tlds[key] = merged + [t for t in extra if t not in merged and t not in remove]
    tlds["medium"] = [t for t in tlds["medium"] if t not in tlds["high"]]

    al = _table(errors, raw, "allow")
    _unknown(errors, "allow", al, {"verified_domains"})
    bl = _table(errors, raw, "block")
    _unknown(errors, "block", bl, {"senders", "domains"})
    allow = {"verified_domains": _domains(errors, "allow.verified_domains", al.get("verified_domains"))}
    block = {"senders": [], "domains": _domains(errors, "block.domains", bl.get("domains"))}
    for s in _list(errors, "block.senders", bl.get("senders")):
        if not ADDRESS_RE.match(s):
            errors.append(f"block.senders: {s!r} is not an e-mail address")
        else:
            block["senders"].append(s.lower())

    dl = _table(errors, raw, "delivery")
    _unknown(errors, "delivery", dl, {"action", "folder", "threshold", "digest", "redirect_to", "keep_copy"})
    base = {"action": "junk", "folder": "Junk", "threshold": "action", "digest": False, "redirect_to": "",
            "keep_copy": False}
    delivery = _policy(errors, "delivery", dl, base)

    mailboxes = []
    raw_mb = raw.get("mailbox", [])
    if not isinstance(raw_mb, list):
        errors.append("mailbox: must be an array of tables ([[mailbox]])")
        raw_mb = []
    seen = set()
    for i, m in enumerate(raw_mb):
        where = f"mailbox[{i}]"
        if not isinstance(m, dict):
            errors.append(f"{where}: must be a table")
            continue
        _unknown(errors, where, m, {"address", "action", "folder", "threshold", "digest", "redirect_to",
                                    "keep_copy", "allow_senders", "block_senders"})
        addr = m.get("address")
        if not isinstance(addr, str) or not ADDRESS_RE.match(addr.strip()):
            errors.append(f"{where}.address: must be an e-mail address")
            continue
        addr = addr.strip().lower()
        if addr in seen:
            errors.append(f"{where}.address: {addr} is listed twice")
            continue
        seen.add(addr)
        pol = _policy(errors, where, m, delivery)
        pol["address"] = addr
        pol["allow_senders"] = _senders(errors, f"{where}.allow_senders", m.get("allow_senders"))
        pol["block_senders"] = _senders(errors, f"{where}.block_senders", m.get("block_senders"))
        if pol["action"] == "redirect":
            if not pol["redirect_to"]:
                errors.append(f"{where}.redirect_to: needed for action = \"redirect\"")
            elif pol["redirect_to"] == addr:
                errors.append(f"{where}.redirect_to: must not be the mailbox itself")
        mailboxes.append(pol)
    by_addr = {m["address"]: m for m in mailboxes}
    for i, m in enumerate(mailboxes):
        target = by_addr.get(m["redirect_to"]) if m["action"] == "redirect" else None
        if target and target["action"] == "redirect":
            errors.append(f"mailbox[{i}].redirect_to: {target['address']} redirects spam too (mail loop)")

    tr = _table(errors, raw, "training")
    _unknown(errors, "training", tr, {"enabled", "mailboxes", "spam_folders", "ham_folders", "spam_mailboxes",
                                      "ham_min_age_days", "spam_max_age_days", "max_per_run", "imapsieve"})
    training = {
        "enabled": _bool(errors, "training.enabled", tr.get("enabled"), True),
        "mailboxes": tr.get("mailboxes", "configured"),
        "spam_folders": _list(errors, "training.spam_folders", tr.get("spam_folders")) or ["Junk"],
        "ham_folders": _list(errors, "training.ham_folders", tr.get("ham_folders")) or ["INBOX"],
        "spam_mailboxes": [],
        "ham_min_age_days": int(_number(errors, "training.ham_min_age_days", tr.get("ham_min_age_days"), 0, 365, 3)),
        "spam_max_age_days": int(_number(errors, "training.spam_max_age_days", tr.get("spam_max_age_days"),
                                         1, 3650, 60)),
        "max_per_run": int(_number(errors, "training.max_per_run", tr.get("max_per_run"), 1, 100000, 500)),
        "imapsieve": _bool(errors, "training.imapsieve", tr.get("imapsieve"), False),
    }
    if training["mailboxes"] not in ("configured", "all"):
        errors.append("training.mailboxes: must be \"configured\" or \"all\"")
    for s in _list(errors, "training.spam_mailboxes", tr.get("spam_mailboxes")):
        if not ADDRESS_RE.match(s):
            errors.append(f"training.spam_mailboxes: {s!r} is not an e-mail address")
        else:
            training["spam_mailboxes"].append(s.lower())
    for key in ("spam_folders", "ham_folders"):
        for f in training[key]:
            if f != "INBOX" and (not FOLDER_RE.match(f) or ".." in f or f.startswith(("/", "."))):
                errors.append(f"training.{key}: {f!r} is not a folder name")

    dg = _table(errors, raw, "digest")
    _unknown(errors, "digest", dg, {"from", "time", "max_items"})
    digest = {"from": "", "time": "07:00", "max_items": 200}
    if "from" in dg:
        if not isinstance(dg["from"], str) or not ADDRESS_RE.match(dg["from"]):
            errors.append("digest.from: must be an e-mail address")
        else:
            digest["from"] = dg["from"].lower()
    if "time" in dg:
        if not isinstance(dg["time"], str) or not TIME_RE.match(dg["time"]):
            errors.append("digest.time: must be HH:MM (24-hour clock)")
        else:
            digest["time"] = dg["time"]
    digest["max_items"] = int(_number(errors, "digest.max_items", dg.get("max_items"), 1, 5000, 200))
    if any(m["digest"] for m in mailboxes) and not digest["from"]:
        errors.append("digest.from: needed when a mailbox has digest = true")

    if errors:
        raise ConfigError(errors)
    # The mailboxes' own domains count as local domains for the personalisation rules.
    for m in mailboxes:
        dom = m["address"].split("@", 1)[1]
        if dom not in rspamd["local_domains"]:
            rspamd["local_domains"].append(dom)
    return {"version": 1, "rspamd": rspamd, "scores": scores, "terms": terms, "brands": brands, "tlds": tlds,
            "allow": allow, "block": block, "delivery": delivery, "mailboxes": mailboxes, "training": training,
            "digest": digest}


def loads(text: str) -> dict:
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError([f"TOML syntax: {exc}"]) from exc
    return normalise(raw)


def load(path: Path) -> dict:
    return loads(Path(path).read_text(encoding="utf-8"))
