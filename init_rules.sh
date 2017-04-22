#!/bin/sh
IPTABLES=/sbin/iptables
MODPROBE=/sbin/modprobe
INT_NET=192.168.1.0/24

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


#####################################
###                               ###
###        OUTPUT CHAIN           ###
###                               ###
#####################################

echo "[+] Setting up OUTPUT chain..."
## STATE TRACKING RULES
$IPTABLES -A OUTPUT -m state --state INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
$IPTABLES -A OUTPUT -m state --state INVALID -j DROP
$IPTABLES -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

## ACCEPT RULES FOR ALLOWING CONNECTIONS OUT
$IPTABLES -A OUTPUT -p tcp --dport 21 --syn -m state --state NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 22 --syn -m state --state NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 25 --syn -m state --state NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 43 --syn -m state --state NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 80 --syn -m state --state NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 443 --syn -m state --state NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 4321 --syn -m state --state NEW -j ACCEPT
$IPTABLES -A OUTPUT -p udp --dport 53 -m state --state NEW -j ACCEPT
$IPTABLES -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT

## DEFAULT OUTPUT LOG RULE
$IPTABLES -A OUTPUT -o ! lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options


#####################################
###                               ###
###        FORWARD CHAIN          ###
###                               ###
#####################################

echo "[+] Setting up FORWARD chain..."
## STATE TRACKING RULES
$IPTABLES -A FORWARD -m state --state INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
$IPTABLES -A FORWARD -m state --state INVALID -j DROP
$IPTABLES -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

## ANTI-SPOOFING RULES
$IPTABLES -A FORWARD -i eth1 -s ! $INT_NET -j LOG --log-prefix "SPOOFED PKT "
$IPTABLES -A FORWARD -i eth1 -s ! $INT_NET -j DROP

## ACCEPT RULES
$IPTABLES -A FORWARD -p tcp --dport 21 --syn -m state --state NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp --dport 22 --syn -m state --state NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp --dport 25 --syn -m state --state NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp --dport 43 --syn -m state --state NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp -dport 80 --syn -m state NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp -dport 443 --syn -m state NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp -i eth1 -s $INT_NET --dport 4321 --syn -m state --state NEW -j ACCEPT
$IPTABLES -A FORWARD -p udp --dport 53 -m state --state NEW -j ACCEPT
$IPTABLES -A FORWARD -p icmp --icmp-type echo-request -j ACCEPT

## DEFAULT FORWARD LOG RULE
$IPTABLES -A FORWARD -o ! lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options


#####################################
###                               ###
###  NETWORD ADDRESS TRANSLATION  ###
###                               ###
#####################################

echo "[+] Setting up NAT chain..."
$IPTABLES -t nat -A PREROUTING -p tcp --dport 80 -i eth0 -h DNAT --to [WEB SERVER IP]:80
$IPTABLES -t nat -A PREROUTING -p tcp --dport 443 -i eth0 -h DNAT --to [WEB SERVER IP]
$IPTABLES -t nat -A PREROUTING -p tcp --dport 53 -i eth0 -h DNAT --to [DNS SERVER IP]:53
$IPTABLES -t nat -A POSTROUTING -s $INT_NET -o eth0 -j MASQUERADE


#####################################
###                               ###
###        FORWARDING             ###
###                               ###
#####################################

echo "[+] Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
