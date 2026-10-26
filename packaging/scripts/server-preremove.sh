#!/bin/sh
# preremove for nexguard-server.deb
set -e

if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    systemctl stop nexguard-server.service >/dev/null 2>&1 || true
    systemctl disable nexguard-server.service >/dev/null 2>&1 || true
fi

exit 0
