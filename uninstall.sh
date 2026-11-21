#!/bin/sh
# Remove everything lumen-spamfilter wrote (after a backup), then test and reload Rspamd and
# Dovecot. Dry run by default; pass --write to remove, --purge to remove the configuration too.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
if [ "$(id -u)" -ne 0 ]; then
    echo "run as root" >&2
    exit 1
fi
if [ -x /usr/local/sbin/lumen-spamfilter ]; then
    exec /usr/local/sbin/lumen-spamfilter uninstall "$@"
fi
exec /usr/bin/python3 -I "$here/bin/lumen-spamfilter" uninstall "$@"
