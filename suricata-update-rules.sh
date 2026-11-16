#!/bin/bash
# Update Suricata IDS rules and live-reload the running engine.
# Runs on the host (root podman). The rules dir is mounted read-write into a
# transient container; the custom config stays read-only. The live engine is
# reloaded with SIGUSR2 only after the new ruleset passes a config test;
# on reload failure Suricata keeps the previous rules active.
set -euo pipefail

RULES=/var/lib/suricata-ids/rules
CONFIG=/var/lib/suricata-ids/config
IMAGE=docker.io/jasonish/suricata

# 1. Update rules (default source: Emerging Threats open) in a transient container.
#    --network host: the container must reach the host's loopback-only unbound for DNS.
podman run --rm --name suricata-rule-update --network host \
  -v "$CONFIG":/etc/suricata/custom:ro,Z \
  -v "$RULES":/etc/suricata/rules:rw,Z \
  --entrypoint /bin/sh \
  "$IMAGE" -c 'suricata-update -o /etc/suricata/rules --no-reload'

# 2. Validate the updated ruleset against the live config before touching the engine.
podman run --rm --name suricata-rule-test --network host \
  -v "$CONFIG":/etc/suricata/custom:ro,Z \
  -v "$RULES":/etc/suricata/rules:ro,Z \
  --entrypoint /bin/sh \
  "$IMAGE" -c 'suricata -T -c /etc/suricata/custom/suricata.yaml -l /tmp'

# 3. Restart the engine (do NOT use SIGUSR2 live-reload here: the transient
#    containers' :Z mounts re-label the config/rules dirs with their own SELinux
#    MCS categories, which makes the running container lose read access and the
#    USR2 reload fail with "Permission denied". A restart re-applies :Z with the
#    fresh container's label and deterministically loads the new rules. Traffic
#    stays flowing meanwhile (NFQUEUE rules use `bypass` = fail-open).
systemctl try-restart suricata.service
echo "Suricata rules updated and engine restarted at $(date -Is)"