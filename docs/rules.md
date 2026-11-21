# Rules

Generated from `lumen_spamfilter/catalog.py` and `lumen_spamfilter/defaults.py` by
`python3 scripts/build_docs.py`; do not edit by hand.

Every rule is an Rspamd symbol named `LUMEN_*`. The scores below are the defaults; change any of
them in the `[scores]` table of the configuration. On KeyHelp the actions are greylist at 4, add
header at 6 and reject at 15. The content rules (group `lumen_spamfilter`) are capped at
`rspamd.group_max_score` (default 12), so they alone never reach the reject score: a reject still
needs evidence from Rspamd's own rules. The allow and block lists (group `lumen_policy`) are not
capped.

Words are matched obfuscation-tolerant: up to two inserted separators between letters (space,
`-`, `_`, `.`, `*`, `·`, `|`, `~`, `+`, soft hyphen, zero-width space/joiner, word joiner, byte
order mark), digit and symbol look-alikes (`0` for o, `3` for e, `1` `!` `|` for i, `5` `$` for
s, `@` `4` for a, `7` for t), Cyrillic look-alike letters, and `ae`/`oe`/`ue`/`ss` or combining
marks for umlauts and ß.

Rules that are informational (score 0) only feed the composite rules next to them.

## Pharma and erectile-dysfunction spam with obfuscated words

| Rule | Score | Type | What it matches |
|---|---|---|---|
| `LUMEN_PHARMA_STRONG` | 3.5 | regexp | Pharma or erectile-dysfunction word in subject or body (obfuscation-tolerant) |
| `LUMEN_PHARMA_WEAK_MULTI` | 1.5 | regexp | At least three weaker pharma words in the body (pills, prescription, pharmacy, ...) |
| `LUMEN_PHARMA_SUBJECT` | 2 | regexp | Pharma word in the subject |
| `LUMEN_OBFUSCATED_TERM` | 3 | regexp | A watched word appears only in obfuscated form (r-ezeptfrei, rez_eptfrei, zero-width or look-alike characters) |
| `LUMEN_ZERO_WIDTH_IN_WORD` | 1.5 | regexp | Zero-width or invisible character between two letters in subject or body |

## Subjects and greetings personalised with the recipient's domain

| Rule | Score | Type | What it matches |
|---|---|---|---|
| `LUMEN_SUBJECT_RCPT_DOMAIN` | 3 | regexp | Subject starts or ends with one of the local (recipient) domains, as in "example.com, Ihr Rezept wartet" |
| `LUMEN_SUBJECT_DOMAIN_GREETING` | 1 | regexp | Subject starts with any domain name followed by a comma |
| `LUMEN_BODY_RCPT_DOMAIN_GREETING` | 1.5 | regexp | Body greets a local domain instead of a person ("Hallo example.com") |

## Display-name brand spoofing

| Rule | Score | Type | What it matches |
|---|---|---|---|
| `LUMEN_BRAND_NAME` | 0 | multimap | Display name contains a known brand (informational, used by LUMEN_BRAND_SPOOF) |
| `LUMEN_BRAND_DOMAIN` | 0 | multimap | From domain is one of the brands' own domains (informational) |
| `LUMEN_BRAND_SPOOF` | 4.5 | composite | Display name claims a brand, but the From domain is not one of the brands' domains |

## Phishing phrases

| Rule | Score | Type | What it matches |
|---|---|---|---|
| `LUMEN_PHISH_REFUND` | 3 | regexp | Refund offer wording with an insurer or contribution context ("Rückerstattung ... Krankenkasse ... beantragen") |
| `LUMEN_PHISH_ACCOUNT_LOCK` | 3 | regexp | "Your account/card has been locked/limited" threats |
| `LUMEN_PHISH_URGENT_VERIFY` | 2 | regexp | Request to verify or confirm combined with a deadline or urgency |
| `LUMEN_PHISH_CRYPTO_WALLET` | 3.5 | regexp | Crypto wallet or recovery phrase combined with verify/synchronise wording |
| `LUMEN_PHISH_CREDENTIALS` | 2.5 | regexp | Asks to enter a PIN, TAN, password or recovery phrase |

## Throwaway domains

| Rule | Score | Type | What it matches |
|---|---|---|---|
| `LUMEN_FROM_TLD_HIGH` | 2 | multimap | From domain is under a top-level domain from the high-risk list |
| `LUMEN_FROM_TLD_MEDIUM` | 1 | multimap | From domain is under a top-level domain from the medium-risk list |
| `LUMEN_AUTH_ON_THROWAWAY` | 1 | composite | Valid DKIM or DMARC on a high-risk top-level domain (cancels the stock authentication bonus: a signature proves the sender, not that the sender is trustworthy) |

## Link tricks

| Rule | Score | Type | What it matches |
|---|---|---|---|
| `LUMEN_URL_BRAND_TOKEN` | 0 | regexp | A link host contains a brand-only token such as "paypal" (informational) |
| `LUMEN_URL_BRAND_HOST` | 0 | multimap | A link points to one of the brands' own domains (informational) |
| `LUMEN_URL_BRAND_LOOKALIKE` | 3 | composite | Link host contains a brand token, and no link goes to a real brand domain |
| `LUMEN_URL_TLD_HIGH` | 1.5 | regexp | A link points to a host under a high-risk top-level domain |
| `LUMEN_URL_USERINFO` | 3 | regexp | Link with user information before the host (`https://bank.example.com@phish.invalid/`) |

## Allow and block lists

| Rule | Score | Type | What it matches |
|---|---|---|---|
| `LUMEN_ALLOW_LISTED` | 0 | multimap | From domain is on the verified allowlist (informational until DMARC passes) |
| `LUMEN_ALLOW_VERIFIED` | -8 | composite | From domain is on the allowlist and DMARC passed (aligned SPF or DKIM) |
| `LUMEN_BLOCK_SENDER` | 10 | multimap | From address is on the blocklist |
| `LUMEN_BLOCK_DOMAIN` | 10 | multimap | From domain is on the blocklist |

## Built-in data

### Pharma words

Strong (score on their own): `rezeptfrei`, `ohne rezept`, `potenzmittel`, `potenzpille`, `potenzprobleme`, `potenzsteigerung`, `erektionsstörung`, `erektion`, `männer-medikament`, `medikamente für männer`, `länger im bett`, `standhaft im bett`, `leistung im bett`, `viagra`, `cialis`, `levitra`, `kamagra`, `sildenafil`, `tadalafil`, `vardenafil`.

Weak (three or more in the body): `pillen`, `potenz`, `rezept`, `apotheke`, `tabletten`, `diskret geliefert`, `diskrete lieferung`, `im bett`, `männer`, `lust`.

Subject-only words: `rezept`, `pillen`, `potenz`, `apotheke`, `männer`.

Add words with `[terms] strong`, `weak` and `subject`; `replace_defaults = true` drops these lists.

### Brands

A display name with one of these names, from a domain outside the listed ones, scores `LUMEN_BRAND_SPOOF`. Banks and insurers that mail from regional domains need those domains added (`[[brands]]` with the same name extends the entry), or the domain on the verified allowlist.

| Brand | Domains | Link tokens |
|---|---|---|
| Sparkasse | sparkasse.de, sparkasse.at, s-finanzgruppe.de | sparkasse |
| Volksbank | volksbank.de, volksbank.at, vr.de | volksbank |
| Raiffeisen | raiffeisen.at, raiffeisen.ch, raiffeisen.de, rbinternational.com | raiffeisen |
| Erste Bank | erstebank.at, sparkasse.at | erstebank |
| BAWAG | bawag.at, bawagpsk.com | bawag |
| Deutsche Bank | db.com, deutsche-bank.de | deutsche-bank |
| Commerzbank | commerzbank.de, commerzbank.com | commerzbank |
| Postbank | postbank.de | postbank |
| ING-DiBa | ing.de, ing.at, ing-diba.de | - |
| N26 | n26.com | - |
| PayPal | paypal.com, paypal.de, paypal.at, paypal-communication.com | paypal |
| Klarna | klarna.com, klarna.de | klarna |
| Amazon | amazon.de, amazon.com, amazon.at, amazon.co.uk, amazon.fr, amazon.it, amazon.es, amazon.nl | - |
| Google | google.com, google.de, google.at, googlemail.com, youtube.com | - |
| Microsoft | microsoft.com, microsoftonline.com, outlook.com, office.com, live.com | - |
| Apple | apple.com, icloud.com, me.com | - |
| Netflix | netflix.com | netflix |
| DHL | dhl.de, dhl.com, dpdhl.com, deutschepost.de | - |
| DPD | dpd.de, dpd.at, dpd.com | - |
| Deutsche Post | deutschepost.de, dhl.de | - |
| Österreichische Post | post.at | - |
| AOK | aok.de | - |
| Techniker Krankenkasse | tk.de | - |
| Barmer | barmer.de | barmer |
| DAK-Gesundheit | dak.de | - |
| IKK classic | ikk-classic.de | - |
| KKH | kkh.de | - |
| ÖGK | gesundheitskasse.at | - |
| Gesundheitskasse | gesundheitskasse.at | - |
| FinanzOnline | bmf.gv.at | - |
| ELSTER | elster.de | - |
| Telekom | telekom.de, telekom.com, t-online.de | - |
| Vodafone | vodafone.de, vodafone.com | - |
| MetaMask | metamask.io, consensys.io, consensys.net | metamask |
| Ledger | ledger.com | - |
| Trezor | trezor.io | trezor |
| Coinbase | coinbase.com | coinbase |
| Binance | binance.com | binance |
| Kraken | kraken.com | - |
| Trust Wallet | trustwallet.com | trustwallet |
| Bitpanda | bitpanda.com | bitpanda |
| DocuSign | docusign.net, docusign.com | docusign |
| Dropbox | dropbox.com, dropboxmail.com | - |
| WhatsApp | whatsapp.com, facebookmail.com, meta.com | - |

### Phishing phrases

Each rule needs one alternative from every part, in the subject or in the body (case-insensitive regular expressions).

- `LUMEN_PHISH_REFUND`: (`r(?:ü|ue)ckerstattung` / `erstattung` / `r(?:ü|ue)ckzahlung` / `gutschrift` / `refund` / `reimbursement`) **and** (`krankenkasse` / `krankenversicherung` / `versicherung` / `gesundheitskasse` / `beitr(?:a|ä|ae)ge?` / `health\s+insurance` / `insurance`) **and** (`beantragen` / `anfordern` / `best(?:ä|ae)tigen` / `steht\s+ihnen\s+zu` / `ausstehend` / `claim` / `erhalten\s+sie` / `jetzt\s+sichern` / `pending`)
- `LUMEN_PHISH_ACCOUNT_LOCK`: (`(?:ihr|ihre|dein|deine|your)\s+(?:\S+\s+){0,2}(?:konto|kundenkonto|account|zugang|karte|kreditkarte|bankkarte|card|credit\s+card|bank\s+account|online-banking|profile|wallet)\s+(?:\S+\s+){0,4}(?:gesperrt|eingeschr(?:ä|ae)nkt|deaktiviert|blockiert|suspendiert|suspended|locked|limited|restricted|disabled|on\s+hold)` / `(?:konto|karten)sperrung` / `sperrung\s+(?:ihres|ihrer|deines|deiner)\s+(?:kontos|karte|zugangs)`)
- `LUMEN_PHISH_URGENT_VERIFY`: (`best(?:ä|ae)tigen` / `verifizieren` / `verifizierung` / `aktualisieren` / `reaktivieren` / `verify` / `confirm` / `validate` / `reactivate`) **and** (`innerhalb\s+(?:von\s+)?(?:24|48|72)\s+stunden` / `within\s+(?:24|48|72)\s+hours` / `umgehend` / `unverz(?:ü|ue)glich` / `sofort` / `immediately` / `dringend` / `urgent` / `letzte\s+(?:warnung|erinnerung|mahnung)` / `final\s+(?:notice|warning)`)
- `LUMEN_PHISH_CRYPTO_WALLET`: (`wallet` / `seed[\s-]?phrase` / `recovery[\s-]phrase` / `secret\s+recovery` / `wiederherstellungsphrase` / `private\s+key` / `ledger\s+live` / `krypto-?wallet` / `crypto\s+wallet`) **and** (`verify` / `verifizieren` / `validate` / `validieren` / `synchroni[sz]e` / `synchronisieren` / `best(?:ä|ae)tigen` / `confirm` / `reactivate` / `migrate` / `migrieren` / `aktualisieren`)
- `LUMEN_PHISH_CREDENTIALS`: (`(?:geben|tragen)\s+sie\s+(?:ihre?n?\s+)?(?:pin|tan|passwort|kennwort|zugangsdaten|seed|kartennummer)` / `enter\s+your\s+(?:password|pin|seed|recovery\s+phrase|card\s+number)` / `(?:pin|tan|passwort|zugangsdaten)\s+(?:eingeben|best(?:ä|ae)tigen)`)

### Top-level domains

High risk: `invalid`, `top`, `icu`, `sbs`, `cfd`, `cyou`, `buzz`, `rest`, `bond`, `click`, `quest`, `monster`, `lol`, `mom`, `autos`, `boats`, `beauty`, `hair`, `skin`, `makeup`, `homes`, `yachts`, `motorcycles`, `cam`, `gq`, `tk`, `ml`, `cf`, `ga`, `work`, `fit`, `loan`, `win`, `bid`, `date`, `racing`, `review`, `stream`, `download`, `men`, `party`, `trade`, `science`, `accountant`, `faith`, `cricket`, `zip`, `mov`.

Medium risk: `xyz`, `shop`, `online`, `site`, `website`, `space`, `fun`, `pw`, `club`, `link`, `best`, `life`, `live`, `today`, `digital`, `email`, `store`.

Change them with `[tlds] extra_high`, `extra_medium` and `remove`.
