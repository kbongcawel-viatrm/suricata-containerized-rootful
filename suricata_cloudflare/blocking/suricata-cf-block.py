#!/usr/bin/env python3
"""Tail Suricata eve.json logs and push flagged public IPs to a Cloudflare List.

Sources:
  - IPS container (NFQUEUE): alerts with alert.action == "blocked"
  - IDS container (AF_PACKET mirror): alerts whose category is a
    high-confidence class (trojan-activity, command-and-control, domain-c2)

Only globally-routable IPs are submitted (RFC1918, loopback, link-local,
multicast, CGNAT, etc. are skipped). IPs are deduplicated against a local
state file and the existing Cloudflare list contents.

Config via environment (see /etc/suricata-ids/cf.env):
  CF_API_TOKEN    required - API token with Account > Cloudflare Lists > Edit
  CF_ACCOUNT_ID   optional - auto-detected if unset
  CF_LIST_NAME    optional - default "suricata_blocked" (created if missing)
  CF_LIST_ID      optional - skip lookup if known
  STATE_FILE      optional - default /var/lib/suricata-ids/cf-block-state.json
"""

import ipaddress
import json
import logging
import os
import sys
import time
import urllib.request
import urllib.error
from collections import deque

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("suricata-cf-block")

CF_API = "https://api.cloudflare.com/client/v4"
POLL_SECONDS = 2
FLUSH_SECONDS = 60
FLUSH_BATCH = 50

IPS_EVE = os.environ.get(
    "IPS_EVE", "/var/lib/containers/storage/volumes/suricata-logs/_data/eve.json")
IDS_EVE = os.environ.get(
    "IDS_EVE", "/var/lib/containers/storage/volumes/suricata-ids-logs/_data/eve.json")

# ARP spoof detection: an IP address must map to exactly one MAC. A second
# MAC claiming the same IP is only treated as an attack when it shows
# *tool-like* behaviour: a sustained flood of conflicting claims. Legit
# events (NIC swaps, phone MAC randomization, buggy IoT) produce a few
# packets; MITM tools (ettercap, bettercap, arpspoof) send hundreds.
#
# The rogue MAC's *own* announced IP is what gets submitted to Cloudflare -
# blocking the victim IP would punish the wrong device.
ARP_BINDING_TTL = 3600          # seconds a binding stays trusted
ARP_RATE_WINDOW = 10.0        # seconds
ARP_RATE_THRESHOLD = 20       # conflicting claims inside the window
ARP_MIN_DURATION = 30.0       # claims must span at least this long
# ARP spoof monitoring is OFF by default - enable explicitly with
# ARP_MONITOR=1 once the detection logic has been validated.
ARP_MONITOR_ENABLED = os.environ.get("ARP_MONITOR", "0") == "1"
ARP_LOG_ONLY = os.environ.get("ARP_LOG_ONLY", "1") == "1"

# Infrastructure IPs whose MAC is known-good. Any *other* MAC claiming one
# of these IPs is an instant flag - there is no legitimate scenario for a
# gateway/infra MAC to change (beyond a hardware swap you WANT alerted on).
PINNED_BINDINGS = {
    "192.168.1.1": "78:5c:72:73:6e:50",   # default gateway (observed MAC)
}

HIGH_CONF_CATEGORIES = {
    "A Network Trojan was detected",                      # trojan-activity
    "Malware Command and Control Activity Detected",     # command-and-control
    "Domain Observed Used for C2 Detected",              # domain-c2
}

TOKEN = os.environ.get("CF_API_TOKEN", "")
ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "")
LIST_NAME = os.environ.get("CF_LIST_NAME", "suricata_blocked")
LIST_ID = os.environ.get("CF_LIST_ID", "")
# Set CF_GATEWAY_LIST=1 to use Zero Trust Gateway lists
# (/gateway/lists) instead of account rules lists (/rules/lists).
GATEWAY_LIST = os.environ.get("CF_GATEWAY_LIST", "") == "1"
STATE_FILE = os.environ.get(
    "STATE_FILE", "/var/lib/suricata-ids/cf-block-state.json")
# Optional: Zero Trust device settings profile ID. When set, submitted IPs
# are also added to that profile's split-tunnel INCLUDE list so traffic to
# them actually traverses Gateway (required when the profile uses include
# mode - a blocklist entry alone does not route the traffic).
WARP_PROFILE_ID = os.environ.get("CF_WARP_PROFILE_ID", "")


def cf_request(method, path, body=None):
    url = f"{CF_API}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {TOKEN}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:500]
        raise RuntimeError(f"CF API {method} {path} -> {e.code}: {detail}")


def detect_account_id():
    global ACCOUNT_ID
    if ACCOUNT_ID:
        return
    resp = cf_request("GET", "/accounts?per_page=50")
    accounts = resp.get("result", [])
    if not accounts:
        raise RuntimeError("No Cloudflare accounts visible to this token")
    if len(accounts) > 1:
        log.warning("Multiple accounts found, using first: %s", accounts[0]["name"])
    ACCOUNT_ID = accounts[0]["id"]
    log.info("Using account %s (%s)", ACCOUNT_ID, accounts[0]["name"])


def find_or_create_list():
    global LIST_ID
    if LIST_ID:
        return
    if GATEWAY_LIST:
        resp = cf_request("GET", f"/accounts/{ACCOUNT_ID}/gateway/lists")
        for lst in resp.get("result", []):
            if lst.get("name") == LIST_NAME:
                LIST_ID = lst["id"]
                log.info("Using existing gateway list %s (%s)", LIST_NAME, LIST_ID)
                return
        resp = cf_request("POST", f"/accounts/{ACCOUNT_ID}/gateway/lists", {
            "name": LIST_NAME,
            "type": "IP",
            "description": "IPs auto-blocked by Suricata IDS/IPS alerts",
        })
        LIST_ID = resp["result"]["id"]
        log.info("Created gateway list %s (%s)", LIST_NAME, LIST_ID)
        return
    cursor = None
    while True:
        path = f"/accounts/{ACCOUNT_ID}/rules/lists?per_page=100"
        if cursor:
            path += f"&cursor={cursor}"
        resp = cf_request("GET", path)
        for lst in resp.get("result", []):
            if lst.get("name") == LIST_NAME:
                LIST_ID = lst["id"]
                log.info("Using existing list %s (%s)", LIST_NAME, LIST_ID)
                return
        info = resp.get("result_info", {})
        cursor = info.get("cursor")
        if not cursor:
            break
    resp = cf_request("POST", f"/accounts/{ACCOUNT_ID}/rules/lists", {
        "name": LIST_NAME,
        "kind": "ip",
        "description": "IPs auto-blocked by Suricata IDS/IPS alerts",
    })
    LIST_ID = resp["result"]["id"]
    log.info("Created list %s (%s)", LIST_NAME, LIST_ID)


def fetch_existing_items():
    """Return set of IPs already in the CF list."""
    existing = set()
    if GATEWAY_LIST:
        resp = cf_request(
            "GET", f"/accounts/{ACCOUNT_ID}/gateway/lists/{LIST_ID}/items")
        for item in resp.get("result") or []:
            val = item.get("value")
            if val:
                existing.add(val)
        log.info("Cloudflare list currently has %d IPs", len(existing))
        return existing
    cursor = None
    while True:
        path = f"/accounts/{ACCOUNT_ID}/rules/lists/{LIST_ID}/items?per_page=1000"
        if cursor:
            path += f"&cursor={cursor}"
        resp = cf_request("GET", path)
        for item in resp.get("result", []):
            ip = item.get("ip")
            if ip:
                existing.add(ip)
        info = resp.get("result_info", {})
        cursor = info.get("cursor")
        if not cursor:
            break
    log.info("Cloudflare list currently has %d IPs", len(existing))
    return existing


def is_public_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return ip.is_global


def load_state():
    try:
        with open(STATE_FILE) as f:
            return set(json.load(f).get("submitted", []))
    except (OSError, json.JSONDecodeError):
        return set()


def save_state(submitted):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"submitted": sorted(submitted)}, f)
    os.replace(tmp, STATE_FILE)


class Tailer:
    """Follows a growing file, tolerating rotation/truncation."""

    def __init__(self, path):
        self.path = path
        self.f = None
        self.offset = 0

    def lines(self):
        try:
            st = os.stat(self.path)
        except OSError:
            return
        if self.f is None or os.fstat(self.f.fileno()).st_ino != st.st_ino:
            self._open()
        elif st.st_size < self.offset:
            self._open()  # truncated
        self.f.seek(self.offset)
        while True:
            line = self.f.readline()
            if not line:
                break
            self.offset = self.f.tell()
            yield line

    def _open(self):
        if self.f:
            self.f.close()
        self.f = open(self.path, "r", errors="replace")
        # Start at EOF: only process new alerts, not backlog.
        self.f.seek(0, os.SEEK_END)
        self.offset = self.f.tell()


def alert_ips(event, is_ips_source):
    """Return set of public IPs to block for a flagged alert, or None."""
    alert = event.get("alert") or {}
    action = alert.get("action")
    category = alert.get("category") or ""

    if is_ips_source:
        if action != "blocked":
            return None
    else:
        if category not in HIGH_CONF_CATEGORIES:
            return None

    ips = set()
    for key in ("src_ip", "dest_ip"):
        ip = event.get(key)
        if ip and is_public_ip(ip):
            ips.add(ip)
    return ips


class ArpMonitor:
    """Tracks IP->MAC bindings from EVE arp events and flags conflicts."""

    def __init__(self):
        self.ip_to_mac = {}        # ip -> (mac, last_seen)
        self.mac_to_ip = {}        # mac -> ip it legitimately claims
        self.claim_times = {}      # (victim_ip, rogue_mac) -> {first_seen, window}
        self.flagged = set()       # (victim_ip, rogue_mac) already reported
        self.pending_arp = {}      # (requester_ip, target_ip) -> timestamp
        self.stats = {"arp_events": 0, "arp_conflicts": 0, "arp_flagged": 0,
                      "arp_unsolicited": 0}

    def observe(self, event):
        """Process one arp event. Returns attacker IP to block, or None."""
        arp = event.get("arp") or {}
        src_ip = arp.get("src_ip")
        src_mac = (arp.get("src_mac") or "").lower()
        opcode = arp.get("opcode")
        if not src_ip or not src_mac or opcode not in ("request", "reply"):
            return None
        self.stats["arp_events"] += 1

        now = time.time()

        # --- Suspicion signals -------------------------------------------
        # Gratuitous ARP: sender and target IP are identical (announcement).
        dest_ip = arp.get("dest_ip")
        is_gratuitous = bool(dest_ip) and src_ip == dest_ip

        # Unsolicited reply: an ARP reply we never saw a matching request
        # for on the mirror (or the request is stale). Strong spoof signal.
        unsolicited = False
        if opcode == "request":
            self.pending_arp[(src_ip, dest_ip)] = now
            if len(self.pending_arp) > 5000:  # bound memory
                cutoff = now - 60
                self.pending_arp = {
                    k: v for k, v in self.pending_arp.items() if v > cutoff}
        elif opcode == "reply":
            ts = self.pending_arp.pop((dest_ip, src_ip), None)
            if ts is None or now - ts > 30:
                unsolicited = True
                self.stats["arp_unsolicited"] += 1

        # Pinned infrastructure bindings: deterministic check, no rate or
        # duration requirement - a wrong MAC on a known-good IP is an
        # instant flag.
        pinned_mac = PINNED_BINDINGS.get(src_ip)
        if pinned_mac is not None:
            if src_mac == pinned_mac:
                self.ip_to_mac[src_ip] = (src_mac, now)
                self.mac_to_ip.setdefault(src_mac, src_ip)
                return None
            self.stats["arp_conflicts"] += 1
            key = (src_ip, src_mac)
            if key in self.flagged:
                return None
            self.flagged.add(key)
            self.stats["arp_flagged"] += 1
            attacker_ip = self.mac_to_ip.get(src_mac)
            log.warning(
                "PINNED BINDING VIOLATION: infra IP %s (expected MAC %s) "
                "claimed by rogue MAC %s, attacker IP %s%s",
                src_ip, pinned_mac, src_mac, attacker_ip or "unknown",
                " [LOG ONLY]" if ARP_LOG_ONLY else "")
            if ARP_LOG_ONLY:
                return None
            if attacker_ip and attacker_ip != src_ip:
                return attacker_ip
            return None

        binding = self.ip_to_mac.get(src_ip)
        fresh = binding is not None and now - binding[1] <= ARP_BINDING_TTL
        bound_mac = binding[0] if fresh else None

        if bound_mac in (None, src_mac):
            # Consistent or first claim - trust it, learn MAC's own IP.
            self.ip_to_mac[src_ip] = (src_mac, now)
            self.mac_to_ip.setdefault(src_mac, src_ip)
            return None

        # Conflicting claim for an already-bound IP. Do NOT let this claim
        # update mac_to_ip - it may be the spoof itself.
        self.stats["arp_conflicts"] += 1
        key = (src_ip, src_mac)
        state = self.claim_times.setdefault(
            key, {"first_seen": None, "window": deque()})
        if state["first_seen"] is None:
            state["first_seen"] = now
        window = state["window"]
        if not window:
            # Fresh burst after a quiet period - restart duration tracking.
            state["first_seen"] = now
        # Gratuitous and unsolicited claims are stronger spoof evidence -
        # weight them so fewer are needed to reach the rate threshold.
        weight = 1 + int(is_gratuitous) + int(unsolicited)
        window.extend([now] * weight)
        while window and now - window[0] > ARP_RATE_WINDOW:
            window.popleft()

        # Require BOTH a flood rate AND sustained duration - the signature
        # of an actual spoofing tool, not a one-off legit change.
        sustained = (now - state["first_seen"]) >= ARP_MIN_DURATION
        if len(window) < ARP_RATE_THRESHOLD or not sustained:
            return None
        if key in self.flagged:
            return None
        self.flagged.add(key)
        self.stats["arp_flagged"] += 1

        attacker_ip = self.mac_to_ip.get(src_mac)
        log.warning(
            "ARP spoof tool behaviour: %s claimed by rogue MAC %s "
            "(%d conflicting claims in %.0fs, legit MAC %s, attacker IP %s)%s",
            src_ip, src_mac, len(window), ARP_RATE_WINDOW,
            bound_mac, attacker_ip or "unknown",
            " [LOG ONLY]" if ARP_LOG_ONLY else "")
        if ARP_LOG_ONLY:
            return None
        # Only return if we resolved the attacker's real IP and it differs
        # from the victim IP.
        if attacker_ip and attacker_ip != src_ip:
            return attacker_ip
        return None


def add_items(ips_with_comments):
    if GATEWAY_LIST:
        items = [{"value": ip, "description": c} for ip, c in ips_with_comments]
        cf_request(
            "PATCH",
            f"/accounts/{ACCOUNT_ID}/gateway/lists/{LIST_ID}",
            {"append": items},
        )
        log.info("Appended %d IPs to gateway list", len(items))
        return True
    items = [{"ip": ip, "comment": c} for ip, c in ips_with_comments]
    resp = cf_request(
        "POST",
        f"/accounts/{ACCOUNT_ID}/rules/lists/{LIST_ID}/items",
        {"items": items},
    )
    n = len(resp.get("result", {}).get("modified", items) or items)
    log.info("Submitted %d IPs to Cloudflare list", len(items))
    return True


def warp_include_sync(ips):
    """Merge IPs into the WARP profile's split-tunnel include list."""
    path = (f"/accounts/{ACCOUNT_ID}/devices/policy/"
            f"{WARP_PROFILE_ID}/include")
    existing = cf_request("GET", path).get("result") or []
    have = {e.get("address") or e.get("host") for e in existing}
    add = []
    for ip in ips:
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            continue
        cidr = f"{ip}/{128 if obj.version == 6 else 32}"
        if cidr not in have:
            add.append({"address": cidr})
    if not add:
        return
    cf_request("PUT", path, existing + add)
    log.info("Added %d IPs to WARP include list", len(add))


def main():
    if not TOKEN:
        log.error("CF_API_TOKEN is not set")
        sys.exit(1)

    detect_account_id()
    find_or_create_list()

    submitted = load_state()
    known = fetch_existing_items() | submitted
    log.info("Tracking %d already-known IPs", len(known))

    tails = {
        IPS_EVE: Tailer(IPS_EVE),
        IDS_EVE: Tailer(IDS_EVE),
    }
    arp_monitor = ArpMonitor()

    pending = {}          # ip -> comment
    warp_pending = set()  # ips awaiting WARP include-list sync
    last_flush = time.time()
    last_warp_sync = 0.0
    last_stats = time.time()
    stats = {"alert_events": 0, "alerts_flagged": 0, "ips_pending": 0,
             "ips_submitted": 0, "api_errors": 0}

    log.info("Watching %s and %s", IPS_EVE, IDS_EVE)
    while True:
        for path, tailer in tails.items():
            is_ips = "suricata-logs" in path
            is_ids = "suricata-ids-logs" in path
            for line in tailer.lines():
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                etype = event.get("event_type")
                if etype == "arp" and is_ids:
                    if not ARP_MONITOR_ENABLED:
                        continue
                    attacker_ip = arp_monitor.observe(event)
                    if attacker_ip:
                        comment = (
                            "suricata arp-spoof: rogue device "
                            f"(see logs for MAC details)"
                        )
                        if attacker_ip not in known and attacker_ip not in pending:
                            pending[attacker_ip] = comment
                            log.info("FLAGGED %s - %s", attacker_ip, comment)
                    continue
                if etype != "alert" or '"event_type":"alert"' not in line:
                    continue
                stats["alert_events"] += 1
                ips = alert_ips(event, is_ips)
                if not ips:
                    continue
                stats["alerts_flagged"] += 1
                sig = (event.get("alert") or {}).get("signature", "?")
                action = (event.get("alert") or {}).get("action", "?")
                src = event.get("src_ip", "?")
                dst = event.get("dest_ip", "?")
                comment = f"suricata {'ips' if is_ips else 'ids'} {action}: {sig} ({src}->{dst})"[:500]
                for ip in ips:
                    if ip not in known and ip not in pending:
                        pending[ip] = comment
                        log.info("FLAGGED %s - %s", ip, comment[:120])

        now = time.time()
        if pending and (len(pending) >= FLUSH_BATCH or now - last_flush >= FLUSH_SECONDS):
            batch = list(pending.items())
            try:
                add_items(batch)
                for ip, _ in batch:
                    known.add(ip)
                    submitted.add(ip)
                stats["ips_submitted"] += len(batch)
                pending.clear()
                if WARP_PROFILE_ID:
                    warp_pending.update(ip for ip, _ in batch)
                save_state(submitted)
                last_flush = now
            except Exception as e:
                stats["api_errors"] += 1
                log.error("Cloudflare submit failed: %s", e)
                time.sleep(30)
        elif warp_pending and now - last_warp_sync >= 60:
            try:
                warp_include_sync(sorted(warp_pending))
                warp_pending.clear()
            except Exception as e:
                stats["api_errors"] += 1
                log.error("WARP include sync failed: %s", e)
            last_warp_sync = now
        else:
            time.sleep(POLL_SECONDS)

        if now - last_stats >= 60:
            last_stats = now
            stats["ips_pending"] = len(pending)
            log.info(
                "STATS alerts=%d flagged=%d pending=%d submitted=%d "
                "known=%d api_errors=%d | arp: events=%d conflicts=%d "
                "unsolicited=%d spoof_flagged=%d bindings=%d",
                stats["alert_events"], stats["alerts_flagged"],
                stats["ips_pending"], stats["ips_submitted"], len(known),
                stats["api_errors"],
                arp_monitor.stats["arp_events"],
                arp_monitor.stats["arp_conflicts"],
                arp_monitor.stats["arp_unsolicited"],
                arp_monitor.stats["arp_flagged"],
                len(arp_monitor.ip_to_mac))


if __name__ == "__main__":
    main()
