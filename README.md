<!-- header:begin: brand-repos 0.1.0, variant studio, files in docs/brand/; the project-page sync drops this block -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/brand/readme-header-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/brand/readme-header-light.svg">
  <img alt="lumen-spamfilter" src="docs/brand/readme-header-light.svg">
</picture>

<!-- byline:studio -->
*a [Luminare Development](https://luminare.tech/open-source/lumen-spamfilter/) open-source project*
<!-- /byline:studio -->
<!-- byline:personal
*by Paul Pasaurek · [project page](https://luminare.tech/open-source/lumen-spamfilter/)*
/byline:personal -->

<!-- header:end -->

# lumen-spamfilter

Configurable spam rules for Rspamd and per-mailbox Sieve delivery on KeyHelp mail servers
(Postfix, Rspamd, Dovecot with Pigeonhole). One TOML file describes the rules, the allow and block
lists and what happens to spam in each mailbox; `lumen-spamfilter apply` turns it into Rspamd
snippets and Sieve scripts, tests them and reloads the services, with a backup of every file it
touches.

[![ci](https://github.com/luminare-dev/lumen-spamfilter/actions/workflows/ci.yml/badge.svg)](https://github.com/luminare-dev/lumen-spamfilter/actions/workflows/ci.yml)
[![licence](https://img.shields.io/github/license/luminare-dev/lumen-spamfilter)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/luminare-dev/lumen-spamfilter/badge)](https://scorecard.dev/viewer/?uri=github.com/luminare-dev/lumen-spamfilter)

## Why

Stock Rspamd misses a family of spam that is common in German-speaking mailboxes: pharma and
erectile-dysfunction mail with words broken up by dashes, underscores or zero-width characters
("r-ezeptfrei", "rez_eptfrei"), subjects that greet the recipient's domain ("example.com, Ihr
Rezept wartet"), display names that claim a bank, health insurer or Google while the address is
somewhere else, and refund, account-lock and wallet-"verify" phishing. Much of it comes from
throwaway domains with valid DKIM, SPF and DMARC, so the stock authentication bonus pushes the
score below zero. lumen-spamfilter adds rules for exactly these patterns and keeps the delivery
decision simple and testable: the Sieve scripts read Rspamd's verdict from `X-Spam-Status`, never
substrings of `X-Spamd-Result` (whose text contains IP addresses and symbol options).

## What it does

- **Rspamd rules** ([docs/rules.md](docs/rules.md)): obfuscation-tolerant pharma words, zero-width
  characters inside words, local domains in subjects and greetings, display-name brand spoofing
  (brand list in a map), phishing phrase groups, high-risk top-level domains for senders and links,
  link tricks (user information before the host, brand look-alike hosts), a DMARC-verified
  allowlist and address and domain blocklists. The content rules are capped (default 12), so a
  reject still needs Rspamd's own evidence.
- **Per-mailbox delivery**: file spam into a folder, redirect it to a spam address (with or without
  a copy), or keep it; threshold per mailbox ("action" or a score); per-mailbox allowed and blocked
  senders; optional daily digest of what was filed.
- **Bayes training**: a systemd timer learns spam from the spam folders and ham from seen inbox
  mail with `rspamc learn_spam` / `learn_ham`, remembering what it learned; optional Dovecot
  IMAPSieve hooks learn when a user moves mail into or out of the spam folder.
- **Settings editor**: [editor/settings.html](editor/settings.html) is one self-contained page (no
  framework, no network requests) that edits the configuration, validates it and shows the
  generated Rspamd and Sieve files.
- **Safe changes**: dry run by default, a backup of every touched file, `rspamadm configtest` on a
  staged copy before writing and on the live tree before reloading, automatic restore when a check
  fails, `rollback` to any backup.

## Quickstart

On the KeyHelp server, as root, from a checkout of this repository:

```sh
./install.sh                         # dry run: shows what would be installed
./install.sh --write                 # program, example config, timers (not enabled)
editor /etc/lumen-spamfilter/config.toml
lumen-spamfilter check               # validates and runs rspamadm configtest on a staged copy
lumen-spamfilter diff                # the exact changes
lumen-spamfilter apply --write       # back up, write, test, reload
```

`lumen-spamfilter rollback --write` restores the files from before the last apply. Details:
[docs/install.md](docs/install.md), all settings: [docs/configuration.md](docs/configuration.md).

## What it writes

| Path | Content |
|---|---|
| `/etc/rspamd/override.d/regexp.conf`, `multimap.conf`, `composites.conf` | the `LUMEN_*` rules (merged with KeyHelp's `local.d` per rule name) |
| `/etc/rspamd/override.d/lumen-spamfilter/*.map` | brand names and domains, TLD lists, allow and block lists |
| `/etc/rspamd/local.d/groups.conf` | the score limit of the rule group (merged; an `override.d` file would replace every stock group) |
| `/etc/dovecot/local.conf` | `sieve_before` for the per-mailbox scripts, optional IMAPSieve settings (KeyHelp reserves this file for the administrator) |
| `/var/lib/lumen-spamfilter/sieve/<domain>/<user>.sieve` | one delivery script per configured mailbox |
| `/var/lib/lumen-spamfilter/backups/` | the backups (`rollback --list`) |

Files that KeyHelp manages (everything it marks "Created by KeyHelp") are never changed. A file
that exists but was not written by lumen-spamfilter is a conflict: `apply` stops unless `--adopt`
is given, and then backs it up first.

## Tests

CI scans a synthetic corpus ([tests/corpus](tests/corpus): hand-written messages, example and
`.invalid` domains only, no real mail) with the official Rspamd 4.3.0 image, pinned by digest. A
small DNS server publishes SPF, DKIM and DMARC records for every sender and the runner signs the
messages, so the spam samples authenticate like spam from throwaway domains does. Every spam sample
must reach add header (score 6) and every ham sample must stay at no action (below the greylist
score 4); a second pass without the score limit checks that each expected rule matches.

| Corpus (Rspamd 4.3.0) | Result | Scores |
|---|---|---|
| 10 spam samples (pharma, brand spoofing, phishing, wallet) | 10 of 10 reach add header or higher | 9.5 to 15.3 |
| 8 ham samples (magazine mailing, payment, code hosting, shipping, personal, bank, insurer) | 8 of 8 no action | -8.0 to 2.99 |
| 3 policy samples (blocklist, verified allowlist, spoofed allowlisted domain) | 3 of 3 as expected | |

The generated Sieve scripts run with Pigeonhole's `sieve-test`, the settings page's JavaScript
generator is checked against the Python generator with node, and the shell scripts with
shellcheck. Run the unit tests with `python3 -m unittest discover -s tests` (standard library
only); the corpus with `python3 scripts/corpus_run.py` (needs docker and openssl).

## Supported versions

| Component | Tested | Expected to work |
|---|---|---|
| KeyHelp | 26.x layout (`/etc/dovecot/conf.keyhelp.d`, `local.conf`) | KeyHelp with Rspamd and Dovecot |
| Rspamd | 4.3.0 | 3.x and 4.x (override.d, multimap selectors, regexp module) |
| Dovecot / Pigeonhole | 2.3.21 / 0.5.21 | 2.3 with Pigeonhole |
| Python | 3.12 | 3.11 or newer (tomllib) |

## Limitations

- The brand list covers the larger German and Austrian banks, insurers, payment and parcel
  services and wallets. Regional banks and insurers send from their own domains; add those
  domains (or put the domain on the verified allowlist) before relying on `LUMEN_BRAND_SPOOF`.
- A per-mailbox threshold above the add header score keeps more mail in the inbox only when
  KeyHelp's own spam move for that mailbox is off; KeyHelp's `after.sieve` still sees
  `X-Spam-Status: Yes`.
- Bayes training needs Rspamd's controller on localhost (KeyHelp's default) and Redis for the
  statistics (KeyHelp's `redis-keyhelp` instance).
- The settings page reads and writes the TOML subset the configuration uses (tables, arrays of
  tables, strings, numbers, booleans and arrays); inline tables and multi-line strings are refused.

## Licence

[Apache-2.0](LICENSE). The licence covers the code only: the project name, logo, header images
and `docs/brand/` are not licensed (see [NOTICE](NOTICE)). Sora is under the SIL Open Font
License 1.1. Not affiliated with or endorsed by Keyweb AG (KeyHelp), the Rspamd project, Dovecot
or Pigeonhole; they are named only to describe what this project works with.

<!-- byline:studio -->
*a [Luminare Development](https://luminare.tech/open-source/lumen-spamfilter/) open-source project*
<!-- /byline:studio -->
<!-- byline:personal
*by Paul Pasaurek · [project page](https://luminare.tech/open-source/lumen-spamfilter/)*
/byline:personal -->
