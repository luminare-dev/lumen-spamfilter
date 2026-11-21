"""Generator tests: configuration validation, word patterns and the rendered Rspamd and Sieve files."""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lumen_spamfilter import catalog, config, patterns, render_dovecot, render_rspamd, render_sieve  # noqa: E402


def rx(pattern: str) -> re.Pattern:
    return re.compile(patterns.to_python(pattern), re.I)


class ConfigTest(unittest.TestCase):
    def test_example_and_corpus_configs_are_valid(self):
        for p in (ROOT / "examples" / "config.toml", ROOT / "tests" / "corpus" / "config.toml"):
            cfg = config.load(p)
            self.assertTrue(cfg["mailboxes"], p)

    def test_empty_config_uses_defaults(self):
        cfg = config.loads("")
        self.assertEqual(cfg["delivery"]["threshold"], "action")
        self.assertEqual(cfg["scores"]["LUMEN_BRAND_SPOOF"], 4.5)
        self.assertIn("rezeptfrei", cfg["terms"]["strong"])

    def test_errors_are_collected(self):
        bad = """
        bogus = 1
        [scores]
        LUMEN_NOPE = 1
        LUMEN_BRAND_SPOOF = "high"
        [[mailbox]]
        address = "not-an-address"
        [[mailbox]]
        address = "a@example.com"
        action = "redirect"
        [[mailbox]]
        address = "b@example.com"
        threshold = -1
        """
        with self.assertRaises(config.ConfigError) as ctx:
            config.loads(bad)
        text = "\n".join(ctx.exception.errors)
        for part in ("bogus: unknown setting", "scores.LUMEN_NOPE", "scores.LUMEN_BRAND_SPOOF: must be a number",
                     "mailbox[0].address", "mailbox[1].redirect_to: needed", "mailbox[2].threshold"):
            self.assertIn(part, text)

    def test_redirect_loop_is_rejected(self):
        with self.assertRaises(config.ConfigError) as ctx:
            config.loads('[[mailbox]]\naddress="a@example.com"\naction="redirect"\nredirect_to="b@example.com"\n'
                         '[[mailbox]]\naddress="b@example.com"\naction="redirect"\nredirect_to="a@example.com"\n')
        self.assertIn("mail loop", str(ctx.exception))

    def test_mailbox_domains_become_local_domains(self):
        cfg = config.loads('[[mailbox]]\naddress = "Info@Example.NET"\n')
        self.assertEqual(cfg["mailboxes"][0]["address"], "info@example.net")
        self.assertIn("example.net", cfg["rspamd"]["local_domains"])

    def test_brand_extends_builtin(self):
        cfg = config.loads('[[brands]]\nname = "paypal"\ndomains = ["paypal.example.com"]\n')
        pp = [b for b in cfg["brands"] if b["name"].lower() == "paypal"]
        self.assertEqual(len(pp), 1)
        self.assertIn("paypal.example.com", pp[0]["domains"])

    def test_digest_needs_sender(self):
        with self.assertRaises(config.ConfigError):
            config.loads('[[mailbox]]\naddress = "a@example.com"\ndigest = true\n')


class PatternTest(unittest.TestCase):
    def test_tolerant_matches_obfuscations(self):
        r = rx(patterns.tolerant("rezeptfrei"))
        for text in ("rezeptfrei", "r-ezeptfrei", "rez_eptfrei", "r​ezeptfrei", "R E Z E P T F R E I",
                     "r3zeptfr3i", "rezept­frei", "rеzeptfrei"):
            self.assertTrue(r.search(text), text)
        self.assertFalse(r.search("rezept frisch"))

    def test_umlauts(self):
        r = rx(patterns.tolerant("männer-medikament"))
        for text in ("Männer-Medikamente", "maenner medikament", "Männermedikament"):
            self.assertTrue(r.search(text), text)
        self.assertFalse(rx(patterns.tolerant("männer")).search("manner"), "English 'manner' is not obfuscated")

    def test_plain_does_not_match_obfuscation(self):
        r = rx(patterns.START + patterns.plain("rezeptfrei"))
        self.assertTrue(r.search("jetzt rezeptfrei"))
        self.assertFalse(r.search("jetzt r-ezeptfrei"))

    def test_start_boundary(self):
        r = rx(patterns.START + patterns.tolerant("potenz"))
        self.assertTrue(r.search("Potenzmittel"))
        self.assertFalse(r.search("Antipotenz"))


class RspamdRenderTest(unittest.TestCase):
    def setUp(self):
        self.cfg = config.load(ROOT / "tests" / "corpus" / "config.toml")
        self.files = render_rspamd.render(self.cfg)

    def test_only_override_d(self):
        self.assertTrue(all(k.startswith("override.d/") for k in self.files), list(self.files))
        for text in self.files.values():
            self.assertIn(render_rspamd.MARKER, text.splitlines()[0])

    def test_every_catalog_symbol_is_rendered(self):
        text = "\n".join(self.files.values())
        for rule in catalog.RULES:
            self.assertRegex(text, rf"(?m)^{rule['symbol']} \{{", rule["symbol"])

    def test_scores_from_config(self):
        cfg = config.loads('[scores]\nLUMEN_PHISH_REFUND = 5.25\n')
        text = render_rspamd.render(cfg)["override.d/regexp.conf"]
        block = text.split("LUMEN_PHISH_REFUND {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("score = 5.25;", block)

    def test_regexes_compile_and_have_no_single_quote(self):
        for symbol, expr in render_rspamd.regexp_rules(self.cfg).items():
            self.assertNotIn("'", expr)
            for atom in re.findall(r"/((?:[^/\\]|\\.)+)/(?:\{\w+\})?[iuH]*", expr):
                re.compile(patterns.to_python(atom), re.I)

    def test_phrases_match_samples(self):
        from lumen_spamfilter.defaults import PHISHING
        samples = {
            "LUMEN_PHISH_ACCOUNT_LOCK": "Ihr Konto wurde vorübergehend gesperrt",
            "LUMEN_PHISH_CRYPTO_WALLET": "please verify your wallet with the secret recovery phrase",
            "LUMEN_PHISH_REFUND": "Rückerstattung Ihrer Krankenkasse jetzt beantragen",
        }
        for symbol, text in samples.items():
            for part in PHISHING[symbol]:
                self.assertTrue(rx(patterns.alternation(part)).search(text), (symbol, part))
        self.assertFalse(rx(patterns.alternation(PHISHING["LUMEN_PHISH_ACCOUNT_LOCK"][0])).search(
            "Account locked after password reset"))

    def test_brand_map(self):
        brand = rx(render_rspamd.brand_regex("PayPal")[1:-3])
        for name in ("PayPal", "Pay Pal Service", "PayPa1", "Kundenservice PAYPAL"):
            self.assertTrue(brand.search(name), name)
        self.assertFalse(rx(render_rspamd.brand_regex("Apple")[1:-3]).search("Applebaum GmbH"))

    def test_local_domain_rules_need_domains(self):
        rules = render_rspamd.regexp_rules(config.loads(""))
        self.assertNotIn("LUMEN_SUBJECT_RCPT_DOMAIN", rules)
        subj = render_rspamd.regexp_rules(self.cfg)["LUMEN_SUBJECT_RCPT_DOMAIN"]
        r = rx(subj[len("Subject=/"):-len("/iuH")])
        self.assertTrue(r.search("example.com, Ihr Rezept wartet"))
        self.assertTrue(r.search("Ihr Rezept wartet - example.net"))
        self.assertFalse(r.search("Neues von example.com im November"))


class SieveRenderTest(unittest.TestCase):
    def test_action_threshold_uses_spam_status(self):
        cfg = config.loads('[[mailbox]]\naddress = "a@example.com"\n')
        text = render_sieve.render(cfg)["example.com/a.sieve"]
        self.assertIn('header :regex "X-Spam-Status" "^Yes, score="', text)
        self.assertNotIn("X-Spamd-Result", text.split("require", 1)[1])
        self.assertNotIn(":contains", text)

    def test_numeric_threshold(self):
        test, _ = render_sieve.spam_test(4.5)
        self.assertIn('"${2}" "4"', test)
        self.assertIn('"${3}" "50"', test)

    def test_redirect_with_copy(self):
        cfg = config.loads('[[mailbox]]\naddress = "a@example.com"\naction = "redirect"\n'
                           'redirect_to = "spam@example.com"\nkeep_copy = true\n')
        text = render_sieve.render(cfg)["example.com/a.sieve"]
        self.assertIn('redirect :copy "spam@example.com";', text)
        self.assertIn('fileinto :create "Junk";', text)

    def test_keep_without_block_has_no_rules(self):
        cfg = config.loads('[[mailbox]]\naddress = "a@example.com"\naction = "keep"\n')
        self.assertNotIn("require", render_sieve.render(cfg)["example.com/a.sieve"])

    def test_dovecot_dropin_extends_plugins(self):
        cfg = config.loads('[training]\nimapsieve = true\n')
        paths = {"sieve_dir": "/s", "imapsieve_dir": "/i", "pipe_dir": "/p", "rspamc": "/usr/bin/rspamc"}
        text = render_dovecot.render(cfg, paths, {"imap_mail_plugins": "quota imap_quota",
                                                  "sieve_before_key": "sieve_before2"})
        self.assertIn("sieve_before2 = /s/%d/%n.sieve", text)
        self.assertIn("mail_plugins = quota imap_quota imap_sieve", text)
        self.assertIn("imapsieve_mailbox2_from = Junk", text)


if __name__ == "__main__":
    unittest.main()
