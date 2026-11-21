FROM docker.io/jasonish/suricata:latest
USER root
RUN dnf install -y arpwatch && dnf clean all
ENTRYPOINT ["/usr/sbin/arpwatch"]
