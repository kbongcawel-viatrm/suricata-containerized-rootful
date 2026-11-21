  ip link set eth1 up promisc on
  ethtool -K eth1 gro off lro off tso off gso off rx off tx off
  ip -br addr
  nmcli device up enp0s20f0u10
  nmcli connection up enp0s20f0u10
  ip a
  ip addr flush dev enp0s20f0u10
  ip addr show eth0
  ip addr show enp0s20f0u10
  nmcli dev set enp0s20f0u10 managed no

