#!/bin/bash

IPTABLES=/sbin/iptables

if [[ $1 ]];
then
	$IPTABLES -I OUTPUT 1 -d $1 -j DROP
	$IPTABLES -I INPUT 1 -s $1 -j DROP
	$IPTABLES -I FORWARD -s $1 -j DROP
	$IPTABLES -I FORWARD -d $1 -j DROP
else
	echo " [-] ban need an argument (./ban [ip.to.ban])"
fi
