# Install, apply, roll back

Every command that changes something is a dry run unless `--write` is given. Run them as root.

## 1. Install the program

```sh
git clone https://github.com/luminare-dev/lumen-spamfilter.git
cd lumen-spamfilter
./install.sh            # dry run
./install.sh --write    # add --enable-timers to start training and digest timers right away
```

`install` checks for the KeyHelp layout (`/etc/keyhelp`, `/etc/dovecot/conf.keyhelp.d`; `--force`
skips the check) and writes, after a backup:

- `/opt/lumen-spamfilter/` (the Python package, standard library only, and the settings page),
- `/usr/local/sbin/lumen-spamfilter` (a two-line wrapper),
- `/etc/lumen-spamfilter/config.toml` (the example, only when no configuration exists),
- `/etc/systemd/system/lumen-spamfilter-{train,digest}.{service,timer}` (not enabled unless
  `--enable-timers`).

It changes no mail configuration.

## 2. Configure and check

Edit `/etc/lumen-spamfilter/config.toml` ([configuration](configuration.md)), or open
`/opt/lumen-spamfilter/editor/settings.html` in a browser on your own computer, edit there and
copy the file to the server.

```sh
lumen-spamfilter check   # validation, conflicts, rspamadm configtest on a staged copy
lumen-spamfilter diff    # unified diff of every file apply would write or remove
```

`check` copies `/etc/rspamd/local.d` and `override.d` to a temporary folder, adds the generated
files and runs `rspamadm --var=LOCAL_CONFDIR=<copy> configtest`. Nothing live is touched.

## 3. Apply

```sh
lumen-spamfilter apply           # dry run: the list of files
lumen-spamfilter apply --write
```

The order is: staged `rspamadm configtest` (stops before writing if it fails), backup of every
file in the plan into `/var/lib/lumen-spamfilter/backups/<time>/` (with a manifest; files that
did not exist are recorded as absent), atomic writes, then `rspamadm configtest`, `doveconf -n`
and `sievec` for every script on the live files. If any of those fail, the backup is restored at
once and nothing is reloaded. Only when all pass are Rspamd and Dovecot reloaded
(`systemctl reload`).

Mailbox scripts of mailboxes that were removed from the configuration are deleted (after the
backup). A file at one of the paths that was not written by lumen-spamfilter (no
`lumen-spamfilter: generated file` marker) is reported as a conflict; `--adopt` replaces it after
the backup.

## 4. Roll back

```sh
lumen-spamfilter rollback --list
lumen-spamfilter rollback --write            # undo the newest backup
lumen-spamfilter rollback 20261121-120000 --write
```

A rollback restores the files as they were before that run, removes the files that run created
(unless someone else has since replaced them), runs the same checks and reloads. It makes a
backup of its own first, so a rollback can be rolled back.

## 5. Training, IMAPSieve and digest

```sh
lumen-spamfilter train            # dry run: how many messages would be learned
lumen-spamfilter train --write
systemctl enable --now lumen-spamfilter-train.timer    # daily at 03:30
```

The training reads messages (it never moves, flags or deletes them) and pipes each new one to
`rspamc learn_spam` or `learn_ham`. `/var/lib/lumen-spamfilter/learned.sqlite` stores the SHA-256
of every learned message, so the next run only sends new ones. The service runs with
`Nice=10`, idle I/O priority and `MemoryMax=256M`.

With `training.imapsieve = true`, `apply` also writes the IMAPSieve settings into
`/etc/dovecot/local.conf` (it extends the current `mail_plugins` of the IMAP protocol, read with
`doveconf`), two Sieve scripts in `/var/lib/lumen-spamfilter/imapsieve/` and two pipe scripts in
`/usr/local/lib/lumen-spamfilter/sieve-pipe/`.

```sh
lumen-spamfilter digest           # dry run
systemctl enable --now lumen-spamfilter-digest.timer   # at digest.time
```

## 6. Uninstall

```sh
./uninstall.sh            # dry run
./uninstall.sh --write    # add --purge to remove the configuration file too
```

It disables the timers and removes every file lumen-spamfilter wrote (Rspamd snippets and maps,
`local.conf` if it is ours, the Sieve scripts, the units, the program), with the same backup,
checks and reloads as `apply`. Backups stay in `/var/lib/lumen-spamfilter/backups/`.
