DynIP Dynamic IP
================

This roll is an attempt to create a reconfigurable frontend.
With this roll installed it is possible to change public ip 
FQDN of a frontend.

This roll is still under heavy development.
Do not use.

Installation
------------

You should install this roll following the standard Rocks installation 
procedure.

To activate the reconfiguration at boot time you need to enable the rocks-dynip 
serice at boot time with:

  chkconfig rocks-dynip on

Finally you will have to create a net\_conf.conf file in the /root direcotry. 
dynip places already a template file in /root/net\_conf.conf_template


```
 public_ip="123.123.123.123"
 netmask="255.255.255.0"
 gw="123.123.123.1"
 dns="8.8.8.8"
 fqdn="testhostname.testdomain.com"
 #use these two entries to specify new mac addresses
 private_mac=""
 public_mac=""
```


rocks reconfigure
-----------------

This command can be used to reconfigure a frontend using a configuration
file with the new network parameters:

   rocks reconfigure net\_conf.conf

This command is called automatically by the rocks-dynip service at boot time.

Frontend with DHCP 
------------------

To have a frontend which works with DHCP it is necessary to activate rocks-dynip at 
boot time as indicated above to create a file in /etc with:

  rouch /etc/rocks-dhcp

After these two steps the frontend will DHCP and reconfigure itself based upon 
it's IP address received from the DHCP





