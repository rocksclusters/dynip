DynIP Dynamic IP
================

This roll is an attempt to create a reconfigurable frontend.
With this roll installed it is possible to change public ip
FQDN of a frontend.

This roll is still under heavy development.
Do not use.

Installation
------------

You should install this roll following the procedure below:

```
git clone https://github.com/rocksclusters/dynip
cd dynip
make roll
rocks add roll dynip-*.iso
rocks enable roll dynip
cd /export/rocks/install
rocks create distro
rocks set attr rocks_dynip true
rocks run roll dynip | bash
```

Finally you will have to create a /root/vc-out.xml file with the appropriate
format. You can find an example file in /root/vc-out.xml.template or at 
pragma_boot https://github.com/pragmagrid/pragma_boot/blob/master/doc/README-old.rst#input-and-output-xml-file-example.


rocks reconfigure
-----------------

This command can be used to reconfigure a frontend using a configuration
file with the new network parameters:

```
   rocks reconfigure /root/vc-out.xml
   mv /root/vc-out.xml /root/vc-out.xml.old
```
   
These commands are called automatically by the rocks-dynip service at boot time.

Frontend with DHCP 
------------------

NOT TESTED YET!

To have a frontend which works with DHCP it is necessary to activate rocks-dynip at 
boot time as indicated above to create a file in /etc with:

```
  touch /etc/rocks-dhcp
```

And set the pubblic interface to dhcp:

```
  rocks set host interface options localhost eth1 dhcp
  rocks report host interface localhost | rocks report script | bash
  reboot 
```

After these two steps the frontend will DHCP and reconfigure itself based upon 
it's IP address received from the DHCP





