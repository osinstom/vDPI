#!/usr/bin/env bash

sudo apt-get update

sudo apt-get install python-pip libpcap-dev libnetfilter-queue-dev git openvswitch-switch

IFACE=$(ifconfig -a | awk '/ens/ {print $1}' | sed -n 2p)

echo -e "auto ${IFACE}\niface ${IFACE} inet dhcp" | sudo tee /etc/network/interfaces.d/${IFACE}.cfg > /dev/null

git clone http://10.254.188.33/diaas/vDPI.git
cd vDPI

sudo pip install -r requirements.txt

sudo ovs-vsctl add-br br0
sudo ovs-vsctl add-port br0 ${IFACE}
sudo ovs-ofctl add-flow br0 in_port=1,action=in_port

sudo python vdpi.py



