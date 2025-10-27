#!/bin/bash

# Create virtual Ethernet pair
ip link add veth0 type veth peer name veth1

# Bring interfaces up
ip link set veth0 up
ip link set veth1 up

# Assign IPv4 addresses
ip addr add 192.168.1.1/24 dev veth0
ip addr add 192.168.1.2/24 dev veth1

# Assign IPv6 addresses
ip addr add 2001:db8::1/64 dev veth0
ip addr add 2001:db8::2/64 dev veth1

# Disable checksum offloading
ethtool --offload veth0 rx off
ethtool --offload veth0 tx off
ethtool --offload veth1 rx off
ethtool --offload veth1 tx off

# Enable IPv6 forwarding (optional, for routing scenarios)
sysctl -w net.ipv6.conf.all.forwarding=1
