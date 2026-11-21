"""The rule catalog: every Rspamd symbol lumen-spamfilter defines, with its default score.

docs/rules.md and the editor page are generated from this list, so the description here is the
one users read. Scores can be changed per symbol in the configuration ([scores]).
"""

from __future__ import annotations

GROUP = "lumen_spamfilter"        # content rules; capped by group_max_score
POLICY_GROUP = "lumen_policy"      # allow and block lists; never capped

# symbol, default score, group, rule type (as written to Rspamd), short description
RULES: list[dict] = [
    # Obfuscated pharma wording
    {"symbol": "LUMEN_PHARMA_STRONG", "score": 3.5, "group": GROUP, "kind": "regexp", "class": "pharma",
     "description": "Pharma or erectile-dysfunction word in subject or body (obfuscation-tolerant)"},
    {"symbol": "LUMEN_PHARMA_WEAK_MULTI", "score": 1.5, "group": GROUP, "kind": "regexp", "class": "pharma",
     "description": "At least three weaker pharma words in the body (pills, prescription, pharmacy, ...)"},
    {"symbol": "LUMEN_PHARMA_SUBJECT", "score": 2.0, "group": GROUP, "kind": "regexp", "class": "pharma",
     "description": "Pharma word in the subject"},
    {"symbol": "LUMEN_OBFUSCATED_TERM", "score": 3.0, "group": GROUP, "kind": "regexp", "class": "pharma",
     "description": "A watched word appears only in obfuscated form (r-ezeptfrei, rez_eptfrei, zero-width or "
                    "look-alike characters)"},
    {"symbol": "LUMEN_ZERO_WIDTH_IN_WORD", "score": 1.5, "group": GROUP, "kind": "regexp", "class": "pharma",
     "description": "Zero-width or invisible character between two letters in subject or body"},
    # Personalisation with the recipient's domain
    {"symbol": "LUMEN_SUBJECT_RCPT_DOMAIN", "score": 3.0, "group": GROUP, "kind": "regexp", "class": "personalised",
     "description": "Subject starts or ends with one of the local (recipient) domains, as in "
                    "\"example.com, Ihr Rezept wartet\""},
    {"symbol": "LUMEN_SUBJECT_DOMAIN_GREETING", "score": 1.0, "group": GROUP, "kind": "regexp",
     "class": "personalised",
     "description": "Subject starts with any domain name followed by a comma"},
    {"symbol": "LUMEN_BODY_RCPT_DOMAIN_GREETING", "score": 1.5, "group": GROUP, "kind": "regexp",
     "class": "personalised",
     "description": "Body greets a local domain instead of a person (\"Hallo example.com\")"},
    # Display-name brand spoofing
    {"symbol": "LUMEN_BRAND_NAME", "score": 0.0, "group": GROUP, "kind": "multimap", "class": "brand",
     "description": "Display name contains a known brand (informational, used by LUMEN_BRAND_SPOOF)"},
    {"symbol": "LUMEN_BRAND_DOMAIN", "score": 0.0, "group": GROUP, "kind": "multimap", "class": "brand",
     "description": "From domain is one of the brands' own domains (informational)"},
    {"symbol": "LUMEN_BRAND_SPOOF", "score": 4.5, "group": GROUP, "kind": "composite", "class": "brand",
     "description": "Display name claims a brand, but the From domain is not one of the brands' domains"},
    {"symbol": "LUMEN_URL_BRAND_TOKEN", "score": 0.0, "group": GROUP, "kind": "regexp", "class": "url",
     "description": "A link host contains a brand-only token such as \"paypal\" (informational)"},
    {"symbol": "LUMEN_URL_BRAND_HOST", "score": 0.0, "group": GROUP, "kind": "multimap", "class": "url",
     "description": "A link points to one of the brands' own domains (informational)"},
    {"symbol": "LUMEN_URL_BRAND_LOOKALIKE", "score": 3.0, "group": GROUP, "kind": "composite", "class": "url",
     "description": "Link host contains a brand token, and no link goes to a real brand domain"},
    # Phishing phrases
    {"symbol": "LUMEN_PHISH_REFUND", "score": 3.0, "group": GROUP, "kind": "regexp", "class": "phishing",
     "description": "Refund offer wording with an insurer or contribution context (\"Rückerstattung ... "
                    "Krankenkasse ... beantragen\")"},
    {"symbol": "LUMEN_PHISH_ACCOUNT_LOCK", "score": 3.0, "group": GROUP, "kind": "regexp", "class": "phishing",
     "description": "\"Your account/card has been locked/limited\" threats"},
    {"symbol": "LUMEN_PHISH_URGENT_VERIFY", "score": 2.0, "group": GROUP, "kind": "regexp", "class": "phishing",
     "description": "Request to verify or confirm combined with a deadline or urgency"},
    {"symbol": "LUMEN_PHISH_CRYPTO_WALLET", "score": 3.5, "group": GROUP, "kind": "regexp", "class": "phishing",
     "description": "Crypto wallet or recovery phrase combined with verify/synchronise wording"},
    {"symbol": "LUMEN_PHISH_CREDENTIALS", "score": 2.5, "group": GROUP, "kind": "regexp", "class": "phishing",
     "description": "Asks to enter a PIN, TAN, password or recovery phrase"},
    # Domains and links
    {"symbol": "LUMEN_FROM_TLD_HIGH", "score": 2.0, "group": GROUP, "kind": "multimap", "class": "domain",
     "description": "From domain is under a top-level domain from the high-risk list"},
    {"symbol": "LUMEN_FROM_TLD_MEDIUM", "score": 1.0, "group": GROUP, "kind": "multimap", "class": "domain",
     "description": "From domain is under a top-level domain from the medium-risk list"},
    {"symbol": "LUMEN_URL_TLD_HIGH", "score": 1.5, "group": GROUP, "kind": "regexp", "class": "url",
     "description": "A link points to a host under a high-risk top-level domain"},
    {"symbol": "LUMEN_AUTH_ON_THROWAWAY", "score": 1.0, "group": GROUP, "kind": "composite", "class": "domain",
     "description": "Valid DKIM or DMARC on a high-risk top-level domain (cancels the stock authentication "
                    "bonus: a signature proves the sender, not that the sender is trustworthy)"},
    {"symbol": "LUMEN_URL_USERINFO", "score": 3.0, "group": GROUP, "kind": "regexp", "class": "url",
     "description": "Link with user information before the host (https://bank.example.com@phish.invalid/)"},
    # Allow and block lists
    {"symbol": "LUMEN_ALLOW_LISTED", "score": 0.0, "group": POLICY_GROUP, "kind": "multimap", "class": "policy",
     "description": "From domain is on the verified allowlist (informational until DMARC passes)"},
    {"symbol": "LUMEN_ALLOW_VERIFIED", "score": -8.0, "group": POLICY_GROUP, "kind": "composite",
     "class": "policy",
     "description": "From domain is on the allowlist and DMARC passed (aligned SPF or DKIM)"},
    {"symbol": "LUMEN_BLOCK_SENDER", "score": 10.0, "group": POLICY_GROUP, "kind": "multimap", "class": "policy",
     "description": "From address is on the blocklist"},
    {"symbol": "LUMEN_BLOCK_DOMAIN", "score": 10.0, "group": POLICY_GROUP, "kind": "multimap", "class": "policy",
     "description": "From domain is on the blocklist"},
]

BY_SYMBOL = {r["symbol"]: r for r in RULES}
CLASSES = {
    "pharma": "Pharma and erectile-dysfunction spam with obfuscated words",
    "personalised": "Subjects and greetings personalised with the recipient's domain",
    "brand": "Display-name brand spoofing",
    "phishing": "Phishing phrases",
    "domain": "Throwaway domains",
    "url": "Link tricks",
    "policy": "Allow and block lists",
}
