<div align="center">

<img src="docs/assets/suricata-logo.png" alt="Suricata" width="420" />

### Observe. Protect. Adapt.

**Suricata IDS running rootful in a Podman container, fed by netfilter NFQUEUE**

[![Suricata](https://img.shields.io/badge/Suricata-IDS%2FIPS-orange?style=flat-square)](https://suricata.io)
[![Rootful](https://img.shields.io/badge/Runtime-Rootful%20Podman-282828?style=flat-square)](etc/containers/systemd/suricata.container)
[![NFQUEUE](https://img.shields.io/badge/Capture-NFQUEUE%20%2B%20nftables%2Ffirewalld-f45a1c?style=flat-square&logo=linux&logoColor=white)](#nfqueue-setup)
[![License](https://img.shields.io/badge/License-GPLv2-6c5c4b?style=flat-square)](LICENSE)

</div>

---

A production-style deployment of [Suricata](https://suricata.io) — the open-source
network threat detection engine by the [OISF](https://oisf.net) — packaged as a
**rootful Podman container** managed by a systemd quadlet. Traffic is steered into
Suricata through **NFQUEUE** rules (nftables or firewalld), and alerts are emitted as
`eve.json` for downstream consumption.

<div align="center">

| 🛡️ **Inline IDS/IPS** | ⚙️ **Rootful Podman** | ♻️ **systemd-native** | 📜 **Full ET ruleset** |
|---|---|---|---|
| Packet inspection via NFQUEUE — no network tap needed | `NET_ADMIN` + `NET_RAW`, `--network=host` | Quadlet unit, `Restart=always`, CPU/memory limits | `suricata.rules` · `urlhaus.rules` · `local.rules` |

</div>

## Repository layout

```
.
├── etc/containers/systemd/
│   └── suricata.container      # Podman quadlet (systemd unit)
├── rules/
│   ├── suricata.rules          # Emerging Threats Open ruleset
│   ├── urlhaus.rules           # URLhaus malware URL rules
│   └── local.rules             # Site-specific rules
├── scripts/
│   ├── nftables-add.sh         #   NFQUEUE rules via nftables
│   ├── nftables-remove.sh      #   Remove nftables table
│   └── firewalld-nfqueue-add.sh#   NFQUEUE rules via firewalld --direct
├── suricata.yaml               # Main Suricata configuration
└── docs/assets/
    └── suricata-logo.png       # OISF trademarked logo (branding use)
```

## How it works

```
NIC ──► nftables / firewalld ──NFQUEUE──► Suricata (container, host net)
                                              │
                                              ▼
                                      /var/log/suricata/eve.json
```

Packets on the monitored interface are queued to Suricata's NFQUEUE listener
(queue `0`, bypass enabled). Rules that match can drop or alert; all events are
written to the `suricata-logs` named volume.

## Deployment

1. Install the quadlet:

   ```bash
   sudo cp etc/containers/systemd/suricata.container \
       /etc/containers/systemd/
   sudo systemctl daemon-reload
   sudo systemctl enable --now suricata
   ```

   Runtime layout expected on the host:

   ```
   /var/lib/suricata-ids/
   ├── config/    # suricata.yaml (mounted to /etc/suricata/custom)
   ├── rules/     # rule files (mounted to /etc/suricata/rules)
   └── logs → named volume suricata-logs → /var/log/suricata
   ```

2. Choose an NFQUEUE backend — **Option A** (nftables) or **Option B** (firewalld):

   <a id="nfqueue-setup"></a>

   ### Option A: nftables table

   ```bash
   sudo ./scripts/nftables-add.sh
   ```

   ### Option B: firewalld direct rules (persistent across reboots)

   ```bash
   sudo ./scripts/firewalld-nfqueue-add.sh
   ```

   Both scripts default to interface `enp1s0` — edit the `IFACE`/`INTERFACE`
   variable at the top of the script to match your NIC.

## Verify

```bash
# Inspect the nftables queue rules
nft list table inet suricata_ids

# …or the firewalld direct rules
firewall-cmd --direct --get-all-rules

# Watch alerts in real time
tail -f /var/lib/containers/storage/volumes/suricata-logs/_data/eve.json

# Container health
systemctl status suricata
podman logs suricata
```

## Tuning

- **`suricata.yaml`** — `HOME_NET`/`EXTERNAL_NET` address groups, rule paths,
  and output settings.
- **Rules** — drop or edit files in `rules/` and reload:

  ```bash
  podman exec suricata suricatasc -c reload-rules
  ```

- **Resources** — `Memory`, `--cpus`, and memory reservations are set in the
  quadlet's `[Container]` section.

## Credits

Suricata and the OISF logo are trademarks of the
[Open Information Security Foundation](https://oisf.net).
Engine: [Suricata](https://suricata.io) · Image: `jasonish/suricata` ·
Licensed under [GPLv2](LICENSE).
