"""Render the Rspamd configuration: override.d snippets and the maps they read.

All files go below Rspamd's $LOCAL_CONFDIR (/etc/rspamd on KeyHelp). Module snippets are written
to override.d/, which KeyHelp leaves alone (it manages local.d/). Rspamd merges override.d with
local.d per key, so the LUMEN_* rules sit next to KeyHelp's own rules without replacing them.
"""

from __future__ import annotations

from . import __version__, catalog
from .defaults import PHISHING
from .patterns import INVISIBLE, START, alternation, domain_regex, plain, tolerant

MARKER = "lumen-spamfilter: generated file"
MAP_DIR = "override.d/lumen-spamfilter"
MAP_REF = "${LOCAL_CONFDIR}/" + MAP_DIR


def header(comment: str = "#") -> str:
    return (f"{comment} {MARKER}\n"
            f"{comment} Written by lumen-spamfilter {__version__}. Do not edit: change the configuration file\n"
            f"{comment} and run \"lumen-spamfilter apply\" (docs/rules.md lists every rule).\n")


def ucl_str(value: str) -> str:
    """A UCL double-quoted string."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def ucl_re(value: str) -> str:
    """A regular expression as a UCL single-quoted string (backslashes stay literal)."""
    if "'" in value:
        raise ValueError(f"regular expression contains a single quote: {value}")
    return "'" + value + "'"


def num(value: float) -> str:
    return f"{value:.2f}".rstrip("0").rstrip(".") if value != int(value) else f"{int(value)}.0"


def subject_or_body(pattern: str) -> str:
    """Rspamd expression: pattern in the decoded Subject or in a decoded text part."""
    return f"(Subject=/{pattern}/iuH | /{pattern}/{{mime}}iu)"


def _block(symbol: str, fields: list[tuple[str, str]]) -> str:
    lines = [f"{symbol} {{"] + [f"  {k} = {v};" for k, v in fields] + ["}", ""]
    return "\n".join(lines)


def _meta(cfg: dict, symbol: str) -> list[tuple[str, str]]:
    rule = catalog.BY_SYMBOL[symbol]
    return [("score", num(cfg["scores"][symbol])), ("group", ucl_str(rule["group"])),
            ("description", ucl_str(rule["description"]))]


def regexp_rules(cfg: dict) -> dict[str, str]:
    """symbol -> Rspamd regexp expression."""
    terms = cfg["terms"]
    rules: dict[str, str] = {}
    strong = START + alternation([tolerant(t) for t in terms["strong"]])
    rules["LUMEN_PHARMA_STRONG"] = subject_or_body(strong)
    if len(terms["weak"]) >= 3:
        atoms = [f"/{START}{tolerant(t)}/{{mime}}iu" for t in terms["weak"]]
        rules["LUMEN_PHARMA_WEAK_MULTI"] = "(" + " + ".join(atoms) + ") >= 3"
    subj = START + alternation([tolerant(t) for t in terms["strong"] + terms["subject"]])
    rules["LUMEN_PHARMA_SUBJECT"] = f"Subject=/{subj}/iuH"
    obf = []
    for t in terms["strong"] + [w for w in terms["weak"] if w not in terms["strong"]]:
        obf.append(f"({subject_or_body(START + tolerant(t))} & !{subject_or_body(START + plain(t))})")
    rules["LUMEN_OBFUSCATED_TERM"] = " | ".join(obf)
    zw = f"[a-zäöüß]{INVISIBLE}+[a-zäöüß]"
    rules["LUMEN_ZERO_WIDTH_IN_WORD"] = subject_or_body(zw)

    local = cfg["rspamd"]["local_domains"]
    if local:
        doms = alternation([domain_regex(d) for d in local])
        rules["LUMEN_SUBJECT_RCPT_DOMAIN"] = (
            f"Subject=/^\\s*(?:www\\.)?{doms}\\s*[,:;!\\-–]|[,:;\\-–]\\s*(?:www\\.)?{doms}\\s*$/iuH")
        rules["LUMEN_BODY_RCPT_DOMAIN_GREETING"] = (
            f"/(?:^|\\s)(?:hallo|hello|hi|hey|liebe[rs]?|sehr\\s+geehrte[rs]?|dear|guten\\s+tag)\\s+"
            f"(?:www\\.)?{doms}(?:$|[\\s,!:.])/{{mime}}iu")
    rules["LUMEN_SUBJECT_DOMAIN_GREETING"] = "Subject=/^\\s*[a-z0-9][a-z0-9-]*(?:\\.[a-z0-9-]+)*\\.[a-z]{2,24}\\s*,/iH"

    for symbol, parts in PHISHING.items():
        rules[symbol] = " & ".join(subject_or_body(alternation(p)) for p in parts)

    url = "^[a-z][a-z0-9+.\\-]*:\\/\\/"
    if cfg["tlds"]["high"]:
        tlds = alternation([domain_regex(t) for t in cfg["tlds"]["high"]])
        rules["LUMEN_URL_TLD_HIGH"] = f"/{url}(?:[^\\/?#@\\s]*@)?[^\\/?#:\\s]+\\.{tlds}\\.?(?::[0-9]+)?(?:[\\/?#]|$)/{{url}}i"
    rules["LUMEN_URL_USERINFO"] = f"/{url}[^\\/?#@\\s]+@[^\\/?#\\s]+/{{url}}i"
    tokens = sorted({t for b in cfg["brands"] for t in b["url_tokens"]})
    if tokens:
        rules["LUMEN_URL_BRAND_TOKEN"] = (
            f"/{url}(?:[^\\/?#@\\s]*@)?[^\\/?#\\s]*{alternation([domain_regex(t) for t in tokens])}/{{url}}i")
    return rules


def composites(cfg: dict) -> dict[str, str]:
    out = {
        "LUMEN_BRAND_SPOOF": "LUMEN_BRAND_NAME & !LUMEN_BRAND_DOMAIN",
        "LUMEN_AUTH_ON_THROWAWAY": "LUMEN_FROM_TLD_HIGH & (R_DKIM_ALLOW | DMARC_POLICY_ALLOW)",
        "LUMEN_ALLOW_VERIFIED": "LUMEN_ALLOW_LISTED & DMARC_POLICY_ALLOW",
    }
    if any(b["url_tokens"] for b in cfg["brands"]):
        out["LUMEN_URL_BRAND_LOOKALIKE"] = "LUMEN_URL_BRAND_TOKEN & !LUMEN_URL_BRAND_HOST"
    return out


def brand_regex(name: str) -> str:
    return f"/{START}{tolerant(name)}(?:$|[^a-z0-9äöüß])/iu"


def maps(cfg: dict) -> dict[str, list[str]]:
    brand_domains = sorted({d for b in cfg["brands"] for d in b["domains"]})
    return {
        "brand_names.map": [f"# {b['name']}\n{brand_regex(b['name'])}" for b in cfg["brands"]],
        "brand_domains.map": brand_domains,
        "tlds_high.map": [f"/\\.{domain_regex(t)}$/i" for t in cfg["tlds"]["high"]],
        "tlds_medium.map": [f"/\\.{domain_regex(t)}$/i" for t in cfg["tlds"]["medium"]],
        "allow_verified_domains.map": cfg["allow"]["verified_domains"],
        "block_senders.map": cfg["block"]["senders"],
        "block_domains.map": cfg["block"]["domains"],
    }


def multimap_rules(cfg: dict) -> list[tuple[str, list[tuple[str, str]]]]:
    def m(name: str) -> str:
        return ucl_str(f"{MAP_REF}/{name}")

    from_mime = [("type", '"from"'), ("extract_from", '"mime"')]
    return [
        ("LUMEN_BRAND_NAME", [("type", '"selector"'), ("selector", ucl_str("from('mime'):name")),
                              ("map", m("brand_names.map")), ("regexp", "true")]),
        ("LUMEN_BRAND_DOMAIN", from_mime + [("filter", '"email:domain:tld"'), ("map", m("brand_domains.map"))]),
        ("LUMEN_URL_BRAND_HOST", [("type", '"url"'), ("filter", '"tld"'), ("map", m("brand_domains.map"))]),
        ("LUMEN_FROM_TLD_HIGH", [("type", '"selector"'), ("selector", ucl_str("from('mime'):domain")),
                                 ("map", m("tlds_high.map")), ("regexp", "true")]),
        ("LUMEN_FROM_TLD_MEDIUM", [("type", '"selector"'), ("selector", ucl_str("from('mime'):domain")),
                                   ("map", m("tlds_medium.map")), ("regexp", "true")]),
        ("LUMEN_ALLOW_LISTED", from_mime + [("filter", '"email:domain:tld"'),
                                            ("map", m("allow_verified_domains.map"))]),
        ("LUMEN_BLOCK_SENDER", from_mime + [("filter", '"email:addr"'), ("map", m("block_senders.map"))]),
        ("LUMEN_BLOCK_DOMAIN", from_mime + [("filter", '"email:domain:tld"'), ("map", m("block_domains.map"))]),
    ]


def render(cfg: dict) -> dict[str, str]:
    """Relative path below $LOCAL_CONFDIR -> file content."""
    files: dict[str, str] = {}

    out = [header()]
    for symbol, expr in regexp_rules(cfg).items():
        out.append(_block(symbol, [("re", ucl_re(expr))] + _meta(cfg, symbol) + [("one_shot", "true")]))
    files["override.d/regexp.conf"] = "\n".join(out)

    out = [header()]
    for symbol, fields in multimap_rules(cfg):
        out.append(_block(symbol, fields + _meta(cfg, symbol)))
    files["override.d/multimap.conf"] = "\n".join(out)

    out = [header()]
    for symbol, expr in composites(cfg).items():
        out.append(_block(symbol, [("expression", ucl_str(expr))] + _meta(cfg, symbol) + [("policy", '"leave"')]))
    files["override.d/composites.conf"] = "\n".join(out)

    files["override.d/groups.conf"] = header() + "\n" + "\n".join([
        f"group {ucl_str(catalog.GROUP)} {{",
        '  description = "lumen-spamfilter content rules";',
        f"  max_score = {num(cfg['rspamd']['group_max_score'])};",
        "}",
        "",
        f"group {ucl_str(catalog.POLICY_GROUP)} {{",
        '  description = "lumen-spamfilter allow and block lists";',
        "}",
        "",
    ])

    for name, lines in maps(cfg).items():
        files[f"{MAP_DIR}/{name}"] = header() + "".join(f"{line}\n" for line in lines)
    return files
