<div align="center">

<img src="docs/assets/suricata-logo.png" alt="Suricata" width="420" />

### Observe. Protect. Adapt.

**Suricata IDS & IPS running rootful in Podman — NFQUEUE inline prevention + AF_PACKET LAN mirror + Cloudflare Gateway enforcement**

[![Suricata](https://img.shields.io/badge/Suricata-IDS%2FIPS-orange?style=flat-square)](https://suricata.io)
[![Rootful](https://img.shields.io/badge/Runtime-Rootful%20Podman-282828?style=flat-square)](suricata_container/suricata.container)
[![NFQUEUE](https://img.shields.io/badge/Capture-NFQUEUE%20%2B%20AF_PACKET-f45a1c?style=flat-square&logo=linux&logoColor=white)](#architecture)
[![Cloudflare](https://img.shields.io/badge/Enforcement-Cloudflare%20Gateway-f38020?style=flat-square&logo=cloudflare&logoColor=white)](#cloudflare-gateway-enforcement)
[![License](https://img.shields.io/badge/License-GPLv2-6c5c4b?style=flat-square)](LICENSE)

</div>

---

A production-style deployment of [Suricata](https://suricata.io) — the open-source
network threat detection engine by the [OISF](https://oisf.net) — packaged as
**rootful Podman containers** managed by systemd quadlets, plus a rootless
Cloudflare integration that turns detections into Gateway-level IP blocks.

## Architecture

```
                        ┌─────────────────────────────┐
                        │   ISP modem / router        │
                        │   (Cloudflare Gateway DNS)  │
                        └───────┬──────────────┬──────┘
                                │              │
              mirrored traffic  │              │  this host's traffic
                                ▼              ▼
   ┌──────────────────────────────────────────────────────────┐
   │  TL-SG105E switch (mirror port)                           │
   │                                                          │
   │   NIC2 ──► suricata-ids (AF_PACKET, passive IDS)  │
   │                                                          │
   │   arpwatch ──► L2 ARP/MAC anomaly alerts (journald)      │
   └──────────────────────────────────────────────────────────┘
                                ▲
   ┌────────────────────────────┴─────────────────────────────┐
   │  THIS HOST                                                │
   │                                                           │
   │   NIC1 ──► nftables/firewalld ──NFQUEUE──► suricata    │
   │   (IPS, inline drop)              (IPS mode)              │
   │                                                           │
   │   warp-cli (include-mode) ──► Cloudflare Zero Trust      │
   │                              Gateway                      │
   └──────────────────────────────────────────────────────────┘
                                │
                                ▼
              suricata-cf-block (rootless container)
              tails both eve.json files
              ├──► suricata_ip_blocklist  (Gateway IP list)
              └──► WARP include list      (split-tunnel routes)
```

### Components

| Component | Mode | Role |
|---|---|---|
| `suricata` | Rootful quadlet, NFQUEUE on `NIC1` | **Inline IPS** — drops malicious traffic to/from this host |
| `suricata-ids` | Rootful quadlet, AF_PACKET on `NIC2` | **Passive IDS** — whole-LAN visibility via switch mirror port (alert-only; cannot block) |
| `arpwatch` | Rootful quadlet, AF_PACKET on `NIC2` | **L2 monitor** — ARP spoofing / MAC-change alerts to journald |
| `suricata-cf-block` | Rootless compose (`suricata-cf-compose.yaml`) | **Enrichment** — tails EVE JSON, submits public IPs to Cloudflare |
| `warp-cli` | Host package (rpm-ostree layer) | **Tunnel** — include-mode split tunnel into Zero Trust Gateway |

### Data flow

1. Suricata IPS/IDS emit `eve.json` alerts (IPS: `alert.action == "blocked"`;
   IDS: high-confidence categories — trojan-activity, C2, domain-c2).
2. `suricata-cf-block` filters to globally-routable IPs, deduplicates against
   a local state file and the live Cloudflare list, and batches submissions.
3. Submitted IPs are appended to the **`suricata_ip_blocklist`** Gateway list
   *and* added to the device profile's **split-tunnel include list** — both
   are required: the include entry routes the traffic into Gateway, the
   blocklist entry makes Gateway kill it.
4. Gateway policy **`suricata block list (l4)`** blocks any connection where
   `ip.src` or `ip.dst` matches the list — enforced at L4, so it works for
   all TCP/UDP regardless of encryption or protocol.

### Key design decisions

- **Include-mode WARP, not full tunnel** — only LAN ranges and flagged IPs
  traverse Gateway. Keeps bandwidth/latency low and blast radius small.
- **L4 filter, not HTTP/DNS** — IP reputation is a layer-3/4 property. The
  HTTP filter would miss encrypted traffic without TLS decryption; DNS
  policies can't match connection destination IPs.
- **ARP path is present but disabled** — `ARP_MONITOR=0` by default; the
  detector has pinned bindings, gratuitous-ARP and unsolicited-reply
  weighting, but stays inert until validated. `arpwatch` covers L2 alerting.
- **Only public IPs are submitted** — RFC1918, loopback, link-local,
  CGNAT, etc. are filtered out (LAN ARP events never reach Cloudflare).

## Repository layout

```
.
├── architecture.html               # Self-contained visual architecture doc
├── suricata-cf-compose.yaml        # Rootless compose for suricata-cf-block
├── suricata_container/
│   ├── suricata.container          # IPS quadlet (NFQUEUE, NIC1)
│   └── suricata-ids.container      # IDS quadlet (AF_PACKET, NIC2)
├── suricata-automated-updates/     # suricata-update rules timer + script
├── suricata_cloudflare/
│   └── blocking/
│       ├── suricata-cf-block.py    # EVE tailer → Cloudflare (deployed copy
│       │                           #   lives at /usr/local/sbin/)
│       └── README.md
├── suricata_configs/               # classification.config, drop.conf
├── suricata_rules/                 # ET Open ruleset + local.rules
├── suricata_yaml/
│   └── suricata.yaml               # Shared config (EVE: alert/dns/http/
│                                   #   tls/flow/stats/arp)
├── arpwatch/
│   ├── arpwatch.container          # L2 ARP monitor quadlet
│   ├── Dockerfile                  # localhost/arpwatch image
│   └── README.md
├── scripts/
│   ├── nftables-add.sh / -remove.sh
│   ├── mirror-nic.sh
│   └── export-logs.md
└── docs/assets/
    └── suricata-logo.png
```

## Host runtime layout

```
/var/lib/suricata-ids/          # IDS config + rules + named log volumes
/etc/containers/systemd/        # suricata.container, suricata-ids.container,
                                #   arpwatch.container (quadlets)
/usr/local/sbin/
├── suricata-cf-block.py        # Cloudflare blocker (mounted into container)
├── suricata-update-rules.sh    # ET rules updater
└── suricata-automated-updates/ # systemd units
/var/lib/suricata-cf-block/
├── cf.env                      # CF_API_TOKEN etc. (mode 600, gitignored)
└── cf-block-state.json         # submitted-IP dedup state
/var/lib/arpwatch-data/arp.dat  # arpwatch learned bindings
```

## Cloudflare Gateway enforcement

- **List**: `suricata_ip_blocklist` (Zero Trust → Gateway → Lists, type IP,
  ~1,000 entry plan limit).
- **Policy**: `suricata block list (l4)`, action `block`,
  traffic `ip.src in $<list> or ip.dst in $<list>`.
- **Device profiles**: split-tunnel **include mode** — `192.168.1.0/24`
  plus auto-added flagged IPs (`/32` IPv4, `/128` IPv6).
- **WARP client**: `warp-cli` layered via rpm-ostree; enrolled to the
  Zero Trust team (`registration new <team-name>`).

> ⚠️ A list entry alone does **not** block traffic — the IP must also be
> routed through Gateway (include list, or exclude-mode full tunnel).
> `suricata-cf-block` handles both automatically when
> `CF_WARP_PROFILE_ID` is set in `cf.env`.

## Operations

```bash
# Container status
systemctl status suricata suricata-ids arpwatch
podman ps --format '{{.Names}} {{.Status}}'

# Live alerts
tail -f /var/lib/containers/storage/volumes/suricata-logs/_data/eve.json
tail -f /var/lib/containers/storage/volumes/suricata-ids-logs/_data/eve.json

# Blocker logs (kim's rootless podman)
sudo -u kim XDG_RUNTIME_DIR=/run/user/1000 \
  podman logs -f suricata-cf-block
journalctl -t arpwatch -f

# WARP
warp-cli status && warp-cli settings | grep -A8 'Include mode'
```

## Verify a block end-to-end

```bash
# Inject a synthetic IDS alert (compact JSON required):
python3 - <<'EOF'
import json
e = {"event_type":"alert","src_ip":"<PUBLIC_TEST_IP>",
     "dest_ip":"192.168.1.50","proto":"TCP",
     "alert":{"action":"allowed",
              "signature":"ET TEST","category":"A Network Trojan was detected"}}
open("/var/lib/containers/storage/volumes/suricata-ids-logs/_data/eve.json","a").write(
    json.dumps(e,separators=(",",":"))+"\n")
EOF

# Within ~60s: FLAGGED → Appended → Added to WARP include list.
# Traffic to that IP is then killed at Gateway (TLS reset / HTTP 000).
```

## Credits

Suricata and the OISF logo are trademarks of the
[Open Information Security Foundation](https://oisf.net).
Engine: [Suricata](https://suricata.io) · Image: `jasonish/suricata` ·
Licensed under [GPLv2](LICENSE).

---

<div align="center">

**Built with [Devin](https://devin.ai)** — AI software engineer by Cognition

</div>
