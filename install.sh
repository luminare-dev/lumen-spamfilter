#!/bin/sh
# Install lumen-spamfilter from this checkout. Dry run by default; pass --write to install.
# It installs the program, an example configuration and the systemd timers (not enabled unless
# --enable-timers is given). It changes no mail configuration: run "lumen-spamfilter apply" for that.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
if [ "$(id -u)" -ne 0 ]; then
    echo "run as root" >&2
    exit 1
fi
exec /usr/bin/python3 -I "$here/bin/lumen-spamfilter" install "$@"
