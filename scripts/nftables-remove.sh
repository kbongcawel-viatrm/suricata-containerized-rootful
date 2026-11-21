#!/usr/bin/bash
set -euo pipefail

echo "[+] Removing Suricata nftables rules..."

nft delete table inet suricata_ids 2>/dev/null || true

echo "[+] Suricata NFQUEUE rules removed."

