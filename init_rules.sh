#!/bin/sh
IPTABLES=/sbin/iptables
MODPROBE=/sbin/modprobe
INT_NET=192.168.10.0/24

#####################################
###                               ###
###        FLUSH                  ###
###                               ###
#####################################

## DELETE EXISTING RULES AND SET CHAIN POLICY SETTING TO DROP
echo "[+] Deleting existing iptables rules..."
$IPTABLES -F
$IPTABLES -F -t nat
$IPTABLES -X
$IPTABLES -P INPUT DROP
$IPTABLES -P OUTPUT DROP
$IPTABLES -F FORWARD DROP

echo "[+] Load connection tracking modules..."
$MODPROBE ip_conntrack
$MODPROBE iptable_nat
$MODPROBE ip_conntrack_ftp
$MODPROBE ip_nat_ftp


#####################################
###                               ###
###        INPUT CHAIN            ###
###                               ###
#####################################

echo "[+] Setting up INPUT chain..."
## STATE TRACKING RULES
$IPTABLES -A INPUT -m state --state INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
$IPTABLES -A INPUT -m state --state INVALID -j DROP
$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

## ANTI-SPOOFING RULES
$IPTABLES -A INPUT -i eth1 -s ! $INT_NET -j LOG --log-prefix "SPOOFED PKT "
$IPTABLES -A INPUT -i eth1 -s ! $INT_NET -j DROP

## ACCEPT RULES
$IPTABLES -A INPUT -i eth1 -p tcp -s $INT_NET --dport 22 --syn -m state --state NEW -j ACCEPT
$IPTABLES -a INPUT -p icmp --icmp-type echo-request -j ACCEPT

## DEFAULT INPUT LOG RULE
$IPTABLES -A INPUT -i ! lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options
