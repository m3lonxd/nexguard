#!/bin/sh
# postinstall for nexguard-agent.deb
set -e

if ! getent passwd nexguard-agent >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --comment "NexGuard agent service account" nexguard-agent
fi

# /etc/nexguard holds agent.yaml, written by a manual `nexguard-agentd
# -enroll ... -config /etc/nexguard/agent.yaml` run (see README.md); left
# root-owned so any admin can run that step, the service reads it back via
# CAP_DAC_READ_SEARCH regardless of the resulting file ownership/mode.
install -d -o root -g root -m 0755 /etc/nexguard

# /var/log/nexguard holds the agent's local JSON Lines action audit log and
# must be writable by the service's own (non-root) user.
install -d -o nexguard-agent -g nexguard-agent -m 0750 /var/log/nexguard

systemctl daemon-reload >/dev/null 2>&1 || true

# Intentionally do NOT enable or start the service here: the binary refuses
# to run until a config file exists at /etc/nexguard/agent.yaml, which only
# `nexguard-agentd -enroll <panel-url> -config /etc/nexguard/agent.yaml`
# (run manually once, see README.md) can create. Enable/start after that:
#   systemctl enable --now nexguard-agent.service

exit 0
