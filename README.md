# Suricata in container (Rootful)

## Applying nfqueue rules.
### Option A: nftables table (what was likely used before)
```
/var/lib/suricata-ids/scripts/nftables-add.sh
 ```
### Option B: firewalld direct rules (persistent across reboots)
```
/var/lib/suricata-ids/scripts/firewalld-nfqueue-add.sh
```

## Verify
```
nft list table inet suricata_ids   # or: firewall-cmd --direct --get-all-rules
tail -f /var/lib/containers/storage/volumes/suricata-logs/_data/eve.json
```


