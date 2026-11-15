
#!/usr/bin/bash
set -euo pipefail

IFACE="enp1s0"
MARK="0x1/0x1"
QUEUE="0"

add_rule() {
    local family="$1"
    local chain="$2"
    local direction="$3"

    if ! firewall-cmd --permanent --direct --query-rule \
        "$family" filter "$chain" 0 \
        "$direction" "$IFACE" \
        -m mark '!' --mark "$MARK" \
        -j NFQUEUE --queue-num "$QUEUE" --queue-bypass
    then
        firewall-cmd --permanent --direct --add-rule \
            "$family" filter "$chain" 0 \
            "$direction" "$IFACE" \
            -m mark '!' --mark "$MARK" \
            -j NFQUEUE --queue-num "$QUEUE" --queue-bypass
    fi
}

echo "[+] Adding IPv4 NFQUEUE rules..."

add_rule ipv4 INPUT -i
add_rule ipv4 OUTPUT -o

echo "[+] Adding IPv6 NFQUEUE rules..."

add_rule ipv6 INPUT -i
add_rule ipv6 OUTPUT -o

echo "[+] Reloading firewalld..."

firewall-cmd --reload

echo "[+] Suricata NFQUEUE rules installed."

