#!/bin/bash

# Define the IP address of the master node
MASTER_NODE_IP="<MASTER_NODE_IP>"

# Update firewall rules
echo "Updating firewall rules to only allow communication with the master node..."

# Flush existing rules
iptables -F

# Allow all traffic to/from the master node
iptables -A INPUT -s $MASTER_NODE_IP -j ACCEPT
iptables -A OUTPUT -d $MASTER_NODE_IP -j ACCEPT

# Block all other incoming and outgoing traffic
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP

# Save the rules to persist after reboot (adjust for your system if necessary)
if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save
    netfilter-persistent reload
elif command -v iptables-save >/dev/null 2>&1; then
    iptables-save > /etc/iptables/rules.v4
else
    echo "Warning: Unable to save firewall rules. Please ensure iptables-persistent or equivalent is installed."
fi

echo "Firewall rules updated successfully. Only the master node can communicate with this IoT device."
