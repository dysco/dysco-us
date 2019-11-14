#!/bin/bash

sudo bash ip_forward.sh

#Host 1
sudo ifconfig h1-0 down
sudo ifconfig h1-0 hw ether 52:54:00:12:34:56
sudo ip link set h1-0 netns h1
sudo ip netns exec h1 ifconfig h1-0 192.168.1.1/24 up
sudo ip netns exec h1 arp -s 192.168.1.254 52:54:00:12:34:56
sudo ip netns exec h1 route add default gw 192.168.1.254

#Host 2
sudo ifconfig h2-0 down
sudo ifconfig h2-0 hw ether 52:54:00:12:34:56
sudo ip link set h2-0 netns h2
sudo ip netns exec h2 ifconfig h2-0 192.168.6.1/24 up
sudo ip netns exec h2 arp -s 192.168.6.254 52:54:00:12:34:56
sudo ip netns exec h2 route add default gw 192.168.6.254

#mb 1
sudo ifconfig mb1-0 down
sudo ifconfig mb1-1 down
sudo ifconfig mb1-0 hw ether 52:54:00:12:34:56
sudo ifconfig mb1-1 hw ether 52:54:00:12:34:56
sudo ip link set mb1-0 netns mb1
sudo ip link set mb1-1 netns mb1
sudo ip netns exec mb1 ifconfig mb1-0 192.168.2.1/24 up
sudo ip netns exec mb1 ifconfig mb1-1 192.168.3.1/24 up
sudo ip netns exec mb1 arp -s 192.168.2.254 52:54:00:12:34:56
sudo ip netns exec mb1 arp -s 192.168.3.254 52:54:00:12:34:56
sudo ip netns exec mb1 route add -net 192.168.1.0/24 gw 192.168.2.254
sudo ip netns exec mb1 route add default gw 192.168.3.254
sudo ip netns exec mb1 bash ip_forward.sh
sudo ip netns exec mb1 tc qdisc del dev mb1-0
sudo ip netns exec mb1 tc qdisc add dev mb1-0 handle 1: root htb default 11
sudo ip netns exec mb1 tc qdisc add dev mb1-0 parent 1: classid 1:1 htb rate 1000mbit
sudo ip netns exec mb1 tc qdisc add dev mb1-0 parent 1:1 classid 1:11 htb rate 1000mbit

#mb 2
sudo ifconfig mb2-0 down
sudo ifconfig mb2-1 down
sudo ifconfig mb2-0 hw ether 52:54:00:12:34:56
sudo ifconfig mb2-1 hw ether 52:54:00:12:34:56
sudo ip link set mb2-0 netns mb2
sudo ip link set mb2-1 netns mb2
sudo ip netns exec mb2 ifconfig mb2-0 192.168.4.1/24 up
sudo ip netns exec mb2 ifconfig mb2-1 192.168.5.1/24 up
sudo ip netns exec mb2 arp -s 192.168.4.254 52:54:00:12:34:56
sudo ip netns exec mb2 arp -s 192.168.5.254 52:54:00:12:34:56
sudo ip netns exec mb2 route add -net 192.168.1.0/24 gw 192.168.4.254
sudo ip netns exec mb2 route add -net 192.168.2.0/24 gw 192.168.4.254
sudo ip netns exec mb2 route add -net 192.168.3.0/24 gw 192.168.4.254
sudo ip netns exec mb2 route add default gw 192.168.5.254
sudo ip netns exec mb2 bash ip_forward.sh
sudo ip netns exec mb2 tc qdisc del dev mb2-0
sudo ip netns exec mb2 tc qdisc add dev mb2-0 handle 1: root htb default 11
sudo ip netns exec mb2 tc qdisc add dev mb2-0 parent 1: classid 1:1 htb rate 500mbit
sudo ip netns exec mb2 tc qdisc add dev mb2-0 parent 1:1 classid 1:11 htb rate 500mbit
