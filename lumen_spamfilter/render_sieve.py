"""Render the per-mailbox Sieve scripts and the IMAPSieve learning scripts.

The delivery decision reads only the X-Spam-Status header that Rspamd's milter_headers module
writes ("Yes, score=7.20" / "No, score=1.10"): "Yes" is the Rspamd action (add header or more),
a numeric threshold compares the score. Rspamd removes any X-Spam-Status header a sender put
into the message before it adds its own. No substring test on X-Spamd-Result is used: its text
contains IP addresses and symbol options, so a test like :contains "[1" matches far too much.
"""

from __future__ import annotations

from . import __version__
from .render_rspamd import MARKER

REQUIRE = ["fileinto", "mailbox", "regex", "variables", "relational", "comparator-i;ascii-numeric", "copy"]


def sieve_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def sieve_list(values: list[str]) -> str:
    return "[" + ", ".join(sieve_str(v) for v in values) + "]"


def header(address: str) -> str:
    return (f"# {MARKER}\n"
            f"# Written by lumen-spamfilter {__version__} for {address}.\n"
            "# Do not edit: change the configuration file and run \"lumen-spamfilter apply\".\n")


def spam_test(threshold) -> tuple[str, str]:
    """(Sieve test, human-readable rule) for a threshold ("action" or a score)."""
    if threshold == "action":
        return ('header :regex "X-Spam-Status" "^Yes, score="',
                "Rspamd's action is add header or higher (X-Spam-Status: Yes)")
    whole = int(threshold)
    frac = int(round((threshold - whole) * 100))
    # X-Spam-Status always has two decimals; negative scores do not match the expression.
    test = ('allof (header :regex "X-Spam-Status" "^(Yes|No), score=([0-9]+)[.]([0-9][0-9])",\n'
            f'         anyof (string :value "gt" :comparator "i;ascii-numeric" "${{2}}" "{whole}",\n'
            f'                allof (string :value "eq" :comparator "i;ascii-numeric" "${{2}}" "{whole}",\n'
            f'                       string :value "ge" :comparator "i;ascii-numeric" "${{3}}" "{frac:02d}")))')
    return test, f"X-Spam-Status score is {threshold:.2f} or more"


def _sender_tests(entries: list[str]) -> list[str]:
    addrs = [e for e in entries if "@" in e]
    doms = [e for e in entries if "@" not in e]
    tests = []
    if addrs:
        tests.append(f'address :all :is "from" {sieve_list(addrs)}')
    if doms:
        tests.append(f'address :domain :is "from" {sieve_list(doms)}')
    return tests


def _anyof(tests: list[str], indent: str) -> str:
    if len(tests) == 1:
        return tests[0]
    sep = f",\n{indent}       "
    return "anyof (" + sep.join(tests) + ")"


def mailbox_script(mb: dict) -> str:
    out = [header(mb["address"])]
    action = mb["action"]
    if action == "keep" and not mb["block_senders"]:
        out.append("# Policy: keep (no spam filing for this mailbox).\n")
        return "".join(out)
    test, rule = spam_test(mb["threshold"])
    if action == "junk":
        what = f"file into \"{mb['folder']}\""
        body = [f'fileinto :create {sieve_str(mb["folder"])};', "stop;"]
    elif action == "redirect":
        what = f"redirect to {mb['redirect_to']}" + (f" and keep a copy in \"{mb['folder']}\"" if mb["keep_copy"] else "")
        if mb["keep_copy"]:
            body = [f'redirect :copy {sieve_str(mb["redirect_to"])};', f'fileinto :create {sieve_str(mb["folder"])};',
                    "stop;"]
        else:
            body = [f'redirect {sieve_str(mb["redirect_to"])};', "stop;"]
    else:
        what = "keep in the inbox"
        body = []
    out.append(f"# Spam: {rule} -> {what}.\n")
    if mb["block_senders"]:
        out.append(f"# Blocked senders -> file into \"{mb['folder']}\".\n")
    if mb["allow_senders"]:
        out.append("# Allowed senders are never filed as spam by this script.\n")
    out.append(f"require {sieve_list(REQUIRE)};\n\n")

    indent = "  " if mb["allow_senders"] else ""
    blocks = []
    if mb["block_senders"]:
        blocks.append(f"{indent}if {_anyof(_sender_tests(mb['block_senders']), indent)} {{\n"
                      f"{indent}  fileinto :create {sieve_str(mb['folder'])};\n{indent}  stop;\n{indent}}}\n")
    if body:
        test_ind = test.replace("\n", "\n" + indent + "   ")
        blocks.append(f"{indent}if {test_ind} {{\n" + "".join(f"{indent}  {b}\n" for b in body) + f"{indent}}}\n")
    if mb["allow_senders"]:
        allow = _anyof(_sender_tests(mb["allow_senders"]), "")
        out.append(f"if not {allow} {{\n" + "".join(blocks) + "}\n")
    else:
        out.append("".join(blocks))
    return "".join(out)


def imapsieve_scripts() -> dict[str, str]:
    """IMAPSieve scripts: moving into the spam folder learns spam, moving out learns ham."""
    head = f"# {MARKER}\n# Written by lumen-spamfilter {__version__}.\n"
    spam = (head + "# Runs when a message is moved or copied into the spam folder: learn it as spam.\n"
            'require ["vnd.dovecot.pipe", "copy", "imapsieve"];\n\n'
            'pipe :copy "lumen-learn-spam";\n')
    ham = (head + "# Runs when a message is moved out of the spam folder: learn it as ham (not for Trash).\n"
           'require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];\n\n'
           'if environment :matches "imap.mailbox" "*" {\n  set "mailbox" "${1}";\n}\n'
           'if string :is "${mailbox}" ["Trash", "Deleted Messages", "Papierkorb"] {\n  stop;\n}\n'
           'pipe :copy "lumen-learn-ham";\n')
    return {"report-spam.sieve": spam, "report-ham.sieve": ham}


def render(cfg: dict) -> dict[str, str]:
    """Relative path (domain/localpart.sieve) -> script, one per configured mailbox."""
    files = {}
    for mb in cfg["mailboxes"]:
        local, domain = mb["address"].split("@", 1)
        files[f"{domain}/{local}.sieve"] = mailbox_script(mb)
    return files
