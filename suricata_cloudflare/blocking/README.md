script:  /usr/local/sbin/suricata-cf-block.py 
Service:  suricata-cf-block.service  (enabled config, not started yet)
Credentials:  /etc/suricata-ids/cf.env  (mode 600)

Container:
   cd /var/home/workspace/suricata-containerized-rootful
   podman compose up -d
   podman logs -f suricata-cf-block

Systemd
systemctl disable --now suricata-cf-block.service   # compose takes over



