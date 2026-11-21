"""Regular expression builders shared by the Rspamd generator (and mirrored in the editor page).

The patterns use PCRE syntax as Rspamd reads it ("\\x{200B}" code points, UTF-8 mode). They avoid
look-behind and \\b, so Rspamd can hand most of them to Hyperscan, and the same text can be
checked with Python's re module after to_python().
"""

from __future__ import annotations

import re

# Characters spammers insert into words: punctuation, spaces, soft hyphen and zero-width characters.
SEP = r"[\s\-_.*·•|~+\x{00AD}\x{200B}-\x{200D}\x{2060}\x{FEFF}]"
# Only the invisible ones (for LUMEN_ZERO_WIDTH_IN_WORD; U+200C is left out, Persian and other
# scripts use it inside words).
INVISIBLE = r"[\x{00AD}\x{200B}\x{200D}\x{2060}\x{FEFF}]"
# A consumed boundary in front of a word (no look-behind).
START = r"(?:^|[^a-z0-9äöüß])"
WORD_CHARS = r"[a-z0-9äöüß]"

# Digit, symbol and Cyrillic look-alikes accepted for a letter.
LOOKALIKES = {
    "a": r"[a\x{0430}@4]",
    "c": r"[c\x{0441}]",
    "e": r"[e\x{0435}3]",
    "i": r"[i\x{0456}1!|]",
    "k": r"[k\x{043A}]",
    "l": r"[l1|]",
    "o": r"[o\x{043E}0]",
    "p": r"[p\x{0440}]",
    "s": r"[s\x{0455}5$]",
    "t": r"[t7]",
    "x": r"[x\x{0445}]",
    "y": r"[y\x{0443}]",
}
UMLAUTS = {
    "ä": r"(?:ä|a\x{0308}|ae)",
    "ö": r"(?:ö|o\x{0308}|oe)",
    "ü": r"(?:ü|u\x{0308}|ue)",
    "ß": r"(?:ß|ss)",
}
PLAIN_UMLAUTS = {"ä": "(?:ä|ae)", "ö": "(?:ö|oe)", "ü": "(?:ü|ue)", "ß": "(?:ß|ss)"}


def _escape_char(ch: str) -> str:
    if ch.isalnum():
        return ch
    return "\\" + ch if ch in r"\^$.|?*+()[]{}/-" else ch


def tolerant(term: str) -> str:
    """A pattern for term that also matches it with separators and look-alike letters inside."""
    out: list[str] = []
    chars = list(term.lower().strip())
    for idx, ch in enumerate(chars):
        if ch == " ":
            out.append(SEP + "{1,3}")
            continue
        if ch == "-":
            out.append(SEP + "{0,3}")
            continue
        out.append(UMLAUTS.get(ch) or LOOKALIKES.get(ch) or _escape_char(ch))
        nxt = chars[idx + 1] if idx + 1 < len(chars) else None
        if nxt is not None and nxt not in " -":
            out.append(SEP + "{0,2}")
    return "".join(out)


def plain(term: str) -> str:
    """The term as normally written (umlauts or their ae/oe/ue spelling, flexible spaces)."""
    out: list[str] = []
    for ch in term.lower().strip():
        if ch == " ":
            out.append(r"\s+")
        elif ch == "-":
            out.append(r"[\s\-]?")
        else:
            out.append(PLAIN_UMLAUTS.get(ch) or _escape_char(ch))
    return "".join(out)


def alternation(parts: list[str]) -> str:
    return "(?:" + "|".join(parts) + ")"


def domain_regex(domain: str) -> str:
    return re.escape(domain.lower()).replace("\\-", "-")


def to_python(pattern: str) -> str:
    """Translate the PCRE-only syntax used here into Python re syntax (for tests)."""
    return re.sub(r"\\x\{([0-9A-Fa-f]{4})\}", lambda m: "\\u" + m.group(1).lower(), pattern)
