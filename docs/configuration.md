# Configuration

One TOML file, `/etc/lumen-spamfilter/config.toml` (start from
[examples/config.toml](../examples/config.toml), or edit it in
[editor/settings.html](../editor/settings.html)). Every setting is optional; an empty file is
valid and gives the built-in rules without any Sieve delivery policy. Unknown settings are errors,
so a typo never goes unnoticed. `lumen-spamfilter check` lists every problem at once.

## `[rspamd]`

| Setting | Default | Meaning |
|---|---|---|
| `local_domains` | `[]` | Domains hosted on the server, for `LUMEN_SUBJECT_RCPT_DOMAIN` and `LUMEN_BODY_RCPT_DOMAIN_GREETING`. The domains of the `[[mailbox]]` entries are added automatically. Without any local domain these two rules are not written. |
| `group_max_score` | `12.0` | Upper limit for the sum of the content rules. Keep it below the reject score (15). |
| `add_header_score` | `6.0` | Rspamd's add header score, for documentation and the editor. |
| `default_brands` | `true` | Use the built-in brand list ([rules](rules.md#brands)). |

## `[scores]`

`SYMBOL = score` for any rule in [rules.md](rules.md), for example `LUMEN_BRAND_SPOOF = 5.0`.

## `[terms]`

`strong`, `weak` and `subject`: extra words, matched obfuscation-tolerant like the built-in ones
(3 to 60 letters, digits, spaces or hyphens). `replace_defaults = true` drops the built-in lists.

## `[[brands]]`

| Setting | Meaning |
|---|---|
| `name` | The name as it appears in display names. Matching tolerates spaces, separators and look-alike letters. A built-in brand with the same name is extended instead of duplicated. |
| `domains` | Registrable domains (eTLD+1) the brand really sends from. |
| `url_tokens` | Optional host name parts only this brand uses, for `LUMEN_URL_BRAND_LOOKALIKE`. |

## `[tlds]`

`extra_high`, `extra_medium` (more top-level domains) and `remove` (leave built-in ones out).

## `[allow]` and `[block]`

| Setting | Meaning |
|---|---|
| `allow.verified_domains` | From domains (subdomains included) that get `LUMEN_ALLOW_VERIFIED` (-8) when DMARC passes. A forged sender never passes DMARC, so this list cannot be abused by spoofing. |
| `block.senders` | From addresses that get `LUMEN_BLOCK_SENDER` (+10). |
| `block.domains` | From domains (subdomains included) that get `LUMEN_BLOCK_DOMAIN` (+10). |

KeyHelp's own global allow and block lists (`KH_GLOBAL_*`) keep working next to these.

## `[delivery]` and `[[mailbox]]`

`[delivery]` sets the defaults; each `[[mailbox]]` can override any of them.

| Setting | Default | Meaning |
|---|---|---|
| `address` | | The mailbox (only in `[[mailbox]]`). |
| `action` | `"junk"` | `junk`: file into `folder`; `redirect`: send to `redirect_to`; `keep`: no filing. |
| `folder` | `"Junk"` | Spam folder (created when missing). |
| `threshold` | `"action"` | `"action"`: spam is what Rspamd marks with the add header action or higher (`X-Spam-Status: Yes`), which also honours KeyHelp's per-account Rspamd settings. A number such as `4.5` compares the score in `X-Spam-Status` instead. |
| `redirect_to` | | Spam address for `action = "redirect"`. A mailbox that redirects to another redirecting mailbox is refused (mail loop). |
| `keep_copy` | `false` | With `redirect`: also file a copy into `folder`. |
| `digest` | `false` | Send a daily digest of what was filed into `folder` (needs `digest.from`). |
| `allow_senders` | `[]` | Addresses or domains (no `@`) never filed as spam for this mailbox. |
| `block_senders` | `[]` | Addresses or domains always filed into `folder` for this mailbox. |

The script runs before the user's own Sieve script (`sieve_before`). It ends processing with
`stop` only when it filed or redirected a message, so vacation replies and the user's own filters
still run for every other message.

## `[training]`

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `true` | `lumen-spamfilter train` does nothing when `false`. |
| `mailboxes` | `"configured"` | Learn from the `[[mailbox]]` entries, or from `"all"` mailboxes below the Dovecot mail location. |
| `spam_folders` | `["Junk"]` | Folders learned as spam. |
| `ham_folders` | `["INBOX"]` | Folders learned as ham: only seen messages (Maildir flag S) at least `ham_min_age_days` old. |
| `spam_mailboxes` | `[]` | Mailboxes whose every message is spam (spam traps, redirect targets). |
| `ham_min_age_days` | `3` | See above. |
| `spam_max_age_days` | `60` | Older spam is not learned. |
| `max_per_run` | `500` | Upper limit of messages sent to `rspamc` per run. |
| `imapsieve` | `false` | Also learn when a user moves mail into the first spam folder (spam) or out of it (ham, except into Trash). |

## `[digest]`

`from` (sender address), `time` (`HH:MM`, used for the timer by `install`) and `max_items`
(default 200). The digest lists date, sender, subject and score only; it has no links.
