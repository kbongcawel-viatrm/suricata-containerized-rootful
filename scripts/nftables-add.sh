#!/usr/bin/bash
set -euo pipefail

INTERFACE="enp1s0"
TABLE="suricata_ids"

echo "[+] Configuring Suricata NFQUEUE..."

# Remove only our own table if it already exists.
nft delete table inet "$TABLE" 2>/dev/null || true

nft -f - <<EOF
table inet $TABLE {
    chain input {
        type filter hook input priority -5; policy accept;

        iifname "$INTERFACE" queue num 0 bypass
    }

    chain output {
        type filter hook output priority -5; policy accept;

        oifname "$INTERFACE" queue num 0 bypass
    }
}
EOF

echo "[+] NFQUEUE 0 configured on $INTERFACE"
echo "[+] Incoming and outgoing traffic selected."

