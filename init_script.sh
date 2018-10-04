#!/usr/bin/env bash

sudo apt-get update

sudo apt-get -qq -y install python-pip git openvswitch-switch

IFACE=$(ifconfig -a | awk '/ens/ {print $1}' | sed -n 2p)

echo -e "auto ${IFACE}\niface ${IFACE} inet dhcp" | sudo tee /etc/network/interfaces.d/${IFACE}.cfg > /dev/null
sudo ifup ${IFACE}

sudo pip install scapy==2.3.2
sudo pip install scapy-ssl_tls
sudo pip install scapy_http

sudo ovs-vsctl add-br br0
sudo ovs-vsctl add-port br0 ${IFACE}
sudo ovs-ofctl add-flow br0 in_port=1,action=in_port

sudo python vdpi.py ${IFACE}



