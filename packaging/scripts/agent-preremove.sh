#!/bin/sh
# preremove for nexguard-agent.deb
set -e

if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    systemctl stop nexguard-agent.service >/dev/null 2>&1 || true
    systemctl disable nexguard-agent.service >/dev/null 2>&1 || true
fi

exit 0
