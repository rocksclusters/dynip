#!/bin/bash
#
# Clem
#
# This script is used to replace the ip address of a frontend
# 



function error(){
    echo -e "Error $1"
    exit 1
}

#
# redirect stdout and stderr 
#
logfile=/var/log/dynip.log
exec > $logfile 2>&1


conf_file="/root/net_conf.conf"

if [ ! -f $conf_file ] && [ -f "/etc/rocks-dhcp" ]; then 
	# we need to generate all the input value from the dhcp issued IPs
	public_interface=`rocks list attr |grep Kickstart_PublicInterface | awk '{print $2}'`
	
	mac=`cat /sys/class/net/$public_interface/address`
	ip=`ifconfig $public_interface |grep "inet "| awk '{ sub(/addr:/, "", $2); print $2 }'`
	net_mask=`ifconfig $public_interface |grep "inet "| awk '{ sub(/Mask:/, "", $4); print $4 }'`
	fqdn=`hostname`
	gw=`ip r|awk '/default/ {print $3}'`
	dns=`awk ' /nameserver/ {print $2}' /etc/resolv.conf | grep -v 127.0.0.1`
	#TODO finsh to fetch the values from the system and write the 
	echo "public_ip=\"$ip\"" > $conf_file
	echo "netmask=\"$net_mask\"" >> $conf_file
	echo "gw=\"gw\"" >> $conf_file
	echo "dns=\"$dns\"" >> $conf_file
	echo "fqdn=\"$fqdn\"" >> $conf_file

fi

/etc/init.d/network stop

/opt/rocks/bin/rocks reconfigure $conf_file

/etc/init.d/network start







