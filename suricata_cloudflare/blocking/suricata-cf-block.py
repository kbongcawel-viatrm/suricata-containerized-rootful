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
  CF_LIST_NAME    optional - default "suricata-blocked" (created if missing)
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("suricata-cf-block")

CF_API = "https://api.cloudflare.com/client/v4"
POLL_SECONDS = 2
FLUSH_SECONDS = 60
FLUSH_BATCH = 50

IPS_EVE = "/var/lib/containers/storage/volumes/suricata-logs/_data/eve.json"
IDS_EVE = "/var/lib/containers/storage/volumes/suricata-ids-logs/_data/eve.json"

HIGH_CONF_CATEGORIES = {
    "A Network Trojan was detected",                      # trojan-activity
    "Malware Command and Control Activity Detected",     # command-and-control
    "Domain Observed Used for C2 Detected",              # domain-c2
}

TOKEN = os.environ.get("CF_API_TOKEN", "")
ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "")
LIST_NAME = os.environ.get("CF_LIST_NAME", "suricata-blocked")
LIST_ID = os.environ.get("CF_LIST_ID", "")
STATE_FILE = os.environ.get(
    "STATE_FILE", "/var/lib/suricata-ids/cf-block-state.json")


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
        for line in self.f:
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


def add_items(ips_with_comments):
    items = [{"ip": ip, "comment": c} for ip, c in ips_with_comments]
    resp = cf_request(
        "POST",
        f"/accounts/{ACCOUNT_ID}/rules/lists/{LIST_ID}/items",
        {"items": items},
    )
    n = len(resp.get("result", {}).get("modified", items) or items)
    log.info("Submitted %d IPs to Cloudflare list", len(items))
    return True


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

    pending = {}          # ip -> comment
    last_flush = time.time()

    log.info("Watching %s and %s", IPS_EVE, IDS_EVE)
    while True:
        for path, tailer in tails.items():
            is_ips = "suricata-logs" in path
            for line in tailer.lines():
                line = line.strip()
                if not line or '"event_type":"alert"' not in line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ips = alert_ips(event, is_ips)
                if not ips:
                    continue
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
                pending.clear()
                save_state(submitted)
                last_flush = now
            except Exception as e:
                log.error("Cloudflare submit failed: %s", e)
                time.sleep(30)
        else:
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
