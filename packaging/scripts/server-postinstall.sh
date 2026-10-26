#!/bin/sh
# postinstall for nexguard-server.deb
set -e

if ! getent passwd nexguard >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --comment "NexGuard server service account" nexguard
fi

# /var/lib/nexguard holds the SQLite database file and must be writable by
# the service's own (non-root) user.
install -d -o nexguard -g nexguard -m 0750 /var/lib/nexguard

systemctl daemon-reload >/dev/null 2>&1 || true

# Intentionally do NOT enable or start the service here, to match the
# agent package's behavior and let the admin choose when to bring the panel
# up:
#   systemctl enable --now nexguard-server.service

exit 0
