"""Built-in rule data: watched words, brands, phishing phrases and top-level domains.

Everything here can be extended (and most of it replaced) from the configuration file. The editor
page embeds the same data (scripts/build_editor.py), so keep it plain JSON-compatible values.
"""

from __future__ import annotations

# Pharma words, matched obfuscation-tolerant (inserted dashes, dots, underscores, spaces,
# zero-width characters, digit and Cyrillic look-alikes). A strong word scores on its own; weak
# words only count when several of them appear together.
PHARMA_STRONG = [
    "rezeptfrei",
    "ohne rezept",
    "potenzmittel",
    "potenzpille",
    "potenzprobleme",
    "potenzsteigerung",
    "erektionsstörung",
    "erektion",
    "männer-medikament",
    "medikamente für männer",
    "länger im bett",
    "standhaft im bett",
    "leistung im bett",
    "viagra",
    "cialis",
    "levitra",
    "kamagra",
    "sildenafil",
    "tadalafil",
    "vardenafil",
]

PHARMA_WEAK = [
    "pillen",
    "potenz",
    "rezept",
    "apotheke",
    "tabletten",
    "diskret geliefert",
    "diskrete lieferung",
    "im bett",
    "männer",
    "lust",
]

# Words that only score in the subject (with the pharma words above).
PHARMA_SUBJECT = ["rezept", "pillen", "potenz", "apotheke", "männer"]

# Brands that phishing mail claims in the display name. "domains" are the registrable domains
# (eTLD+1) the brand really sends from; mail from any other domain with the brand in the display
# name is flagged. "url_tokens" are host name parts that only the brand uses, for look-alike links
# (left empty where the word is common in unrelated host names).
BRANDS = [
    {"name": "Sparkasse", "domains": ["sparkasse.de", "sparkasse.at", "s-finanzgruppe.de"],
     "url_tokens": ["sparkasse"]},
    {"name": "Volksbank", "domains": ["volksbank.de", "volksbank.at", "vr.de"], "url_tokens": ["volksbank"]},
    {"name": "Raiffeisen", "domains": ["raiffeisen.at", "raiffeisen.ch", "raiffeisen.de", "rbinternational.com"],
     "url_tokens": ["raiffeisen"]},
    {"name": "Erste Bank", "domains": ["erstebank.at", "sparkasse.at"], "url_tokens": ["erstebank"]},
    {"name": "BAWAG", "domains": ["bawag.at", "bawagpsk.com"], "url_tokens": ["bawag"]},
    {"name": "Deutsche Bank", "domains": ["db.com", "deutsche-bank.de"], "url_tokens": ["deutsche-bank"]},
    {"name": "Commerzbank", "domains": ["commerzbank.de", "commerzbank.com"], "url_tokens": ["commerzbank"]},
    {"name": "Postbank", "domains": ["postbank.de"], "url_tokens": ["postbank"]},
    {"name": "ING-DiBa", "domains": ["ing.de", "ing.at", "ing-diba.de"], "url_tokens": []},
    {"name": "N26", "domains": ["n26.com"], "url_tokens": []},
    {"name": "PayPal", "domains": ["paypal.com", "paypal.de", "paypal.at", "paypal-communication.com"],
     "url_tokens": ["paypal"]},
    {"name": "Klarna", "domains": ["klarna.com", "klarna.de"], "url_tokens": ["klarna"]},
    {"name": "Amazon", "domains": ["amazon.de", "amazon.com", "amazon.at", "amazon.co.uk", "amazon.fr",
                                   "amazon.it", "amazon.es", "amazon.nl"], "url_tokens": []},
    {"name": "Google", "domains": ["google.com", "google.de", "google.at", "googlemail.com", "youtube.com"],
     "url_tokens": []},
    {"name": "Microsoft", "domains": ["microsoft.com", "microsoftonline.com", "outlook.com", "office.com",
                                      "live.com"], "url_tokens": []},
    {"name": "Apple", "domains": ["apple.com", "icloud.com", "me.com"], "url_tokens": []},
    {"name": "Netflix", "domains": ["netflix.com"], "url_tokens": ["netflix"]},
    {"name": "DHL", "domains": ["dhl.de", "dhl.com", "dpdhl.com", "deutschepost.de"], "url_tokens": []},
    {"name": "DPD", "domains": ["dpd.de", "dpd.at", "dpd.com"], "url_tokens": []},
    {"name": "Deutsche Post", "domains": ["deutschepost.de", "dhl.de"], "url_tokens": []},
    {"name": "Österreichische Post", "domains": ["post.at"], "url_tokens": []},
    {"name": "AOK", "domains": ["aok.de"], "url_tokens": []},
    {"name": "Techniker Krankenkasse", "domains": ["tk.de"], "url_tokens": []},
    {"name": "Barmer", "domains": ["barmer.de"], "url_tokens": ["barmer"]},
    {"name": "DAK-Gesundheit", "domains": ["dak.de"], "url_tokens": []},
    {"name": "IKK classic", "domains": ["ikk-classic.de"], "url_tokens": []},
    {"name": "KKH", "domains": ["kkh.de"], "url_tokens": []},
    {"name": "ÖGK", "domains": ["gesundheitskasse.at"], "url_tokens": []},
    {"name": "Gesundheitskasse", "domains": ["gesundheitskasse.at"], "url_tokens": []},
    {"name": "FinanzOnline", "domains": ["bmf.gv.at"], "url_tokens": []},
    {"name": "ELSTER", "domains": ["elster.de"], "url_tokens": []},
    {"name": "Telekom", "domains": ["telekom.de", "telekom.com", "t-online.de"], "url_tokens": []},
    {"name": "Vodafone", "domains": ["vodafone.de", "vodafone.com"], "url_tokens": []},
    {"name": "MetaMask", "domains": ["metamask.io", "consensys.io", "consensys.net"], "url_tokens": ["metamask"]},
    {"name": "Ledger", "domains": ["ledger.com"], "url_tokens": []},
    {"name": "Trezor", "domains": ["trezor.io"], "url_tokens": ["trezor"]},
    {"name": "Coinbase", "domains": ["coinbase.com"], "url_tokens": ["coinbase"]},
    {"name": "Binance", "domains": ["binance.com"], "url_tokens": ["binance"]},
    {"name": "Kraken", "domains": ["kraken.com"], "url_tokens": []},
    {"name": "Trust Wallet", "domains": ["trustwallet.com"], "url_tokens": ["trustwallet"]},
    {"name": "Bitpanda", "domains": ["bitpanda.com"], "url_tokens": ["bitpanda"]},
    {"name": "DocuSign", "domains": ["docusign.net", "docusign.com"], "url_tokens": ["docusign"]},
    {"name": "Dropbox", "domains": ["dropbox.com", "dropboxmail.com"], "url_tokens": []},
    {"name": "WhatsApp", "domains": ["whatsapp.com", "facebookmail.com", "meta.com"], "url_tokens": []},
]

# Phishing phrase groups. Each group is a list of "all of" parts; every part is a list of
# alternatives (plain regular expression fragments, case-insensitive, "\s+" between words).
PHISHING = {
    "LUMEN_PHISH_REFUND": [
        [r"r(?:ü|ue)ckerstattung", r"erstattung", r"r(?:ü|ue)ckzahlung", r"gutschrift", r"refund",
         r"reimbursement"],
        [r"krankenkasse", r"krankenversicherung", r"versicherung", r"gesundheitskasse", r"beitr(?:a|ä|ae)ge?",
         r"health\s+insurance", r"insurance"],
        [r"beantragen", r"anfordern", r"best(?:ä|ae)tigen", r"steht\s+ihnen\s+zu", r"ausstehend", r"claim",
         r"erhalten\s+sie", r"jetzt\s+sichern", r"pending"],
    ],
    "LUMEN_PHISH_ACCOUNT_LOCK": [
        [r"(?:ihr|ihre|dein|deine|your)\s+(?:\S+\s+){0,2}(?:konto|kundenkonto|account|zugang|karte|kreditkarte|"
         r"bankkarte|online-banking|wallet)\s+(?:\S+\s+){0,4}(?:gesperrt|eingeschr(?:ä|ae)nkt|deaktiviert|"
         r"blockiert|suspendiert|suspended|locked|limited|restricted|disabled|on\s+hold)",
         r"(?:konto|karten)sperrung", r"sperrung\s+(?:ihres|ihrer|deines|deiner)\s+(?:kontos|karte|zugangs)"],
    ],
    "LUMEN_PHISH_URGENT_VERIFY": [
        [r"best(?:ä|ae)tigen", r"verifizieren", r"verifizierung", r"aktualisieren", r"reaktivieren", r"verify",
         r"confirm", r"validate", r"reactivate"],
        [r"innerhalb\s+(?:von\s+)?(?:24|48|72)\s+stunden", r"within\s+(?:24|48|72)\s+hours", r"umgehend",
         r"unverz(?:ü|ue)glich", r"sofort", r"immediately", r"dringend", r"urgent",
         r"letzte\s+(?:warnung|erinnerung|mahnung)", r"final\s+(?:notice|warning)"],
    ],
    "LUMEN_PHISH_CRYPTO_WALLET": [
        [r"wallet", r"seed[\s-]?phrase", r"recovery[\s-]phrase", r"secret\s+recovery", r"wiederherstellungsphrase",
         r"private\s+key", r"ledger\s+live", r"krypto-?wallet", r"crypto\s+wallet"],
        [r"verify", r"verifizieren", r"validate", r"validieren", r"synchroni[sz]e", r"synchronisieren",
         r"best(?:ä|ae)tigen", r"confirm", r"reactivate", r"migrate", r"migrieren", r"aktualisieren"],
    ],
    "LUMEN_PHISH_CREDENTIALS": [
        [r"(?:geben|tragen)\s+sie\s+(?:ihre?n?\s+)?(?:pin|tan|passwort|kennwort|zugangsdaten|seed|kartennummer)",
         r"enter\s+your\s+(?:password|pin|seed|recovery\s+phrase|card\s+number)",
         r"(?:pin|tan|passwort|zugangsdaten)\s+(?:eingeben|best(?:ä|ae)tigen)"],
    ],
}

# Top-level domains with a high share of throwaway registrations. "high" scores more than
# "medium"; .invalid never carries real mail. Tune both lists to your mail.
TLDS_HIGH = [
    "invalid", "top", "icu", "sbs", "cfd", "cyou", "buzz", "rest", "bond", "click", "quest", "monster",
    "lol", "mom", "autos", "boats", "beauty", "hair", "skin", "makeup", "homes", "yachts", "motorcycles",
    "cam", "gq", "tk", "ml", "cf", "ga", "work", "fit", "loan", "win", "bid", "date", "racing", "review",
    "stream", "download", "men", "party", "trade", "science", "accountant", "faith", "cricket", "zip", "mov",
]
TLDS_MEDIUM = [
    "xyz", "shop", "online", "site", "website", "space", "fun", "pw", "club", "link", "best", "life", "live",
    "today", "digital", "email", "store",
]
