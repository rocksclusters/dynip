# $Id: __init__.py,v 1.23 2012/11/27 00:48:12 phil Exp $
#
# @Copyright@
# 
# 				Rocks(r)
# 		         www.rocksclusters.org
# 		         version 5.6 (Emerald Boa)
# 		         version 6.1 (Emerald Boa)
# 
# Copyright (c) 2000 - 2013 The Regents of the University of California.
# All rights reserved.	
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# 
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright
# notice unmodified and in its entirety, this list of conditions and the
# following disclaimer in the documentation and/or other materials provided 
# with the distribution.
# 
# 3. All advertising and press materials, printed or electronic, mentioning
# features or use of this software must display the following acknowledgement: 
# 
# 	"This product includes software developed by the Rocks(r)
# 	Cluster Group at the San Diego Supercomputer Center at the
# 	University of California, San Diego and its contributors."
# 
# 4. Except as permitted for the purposes of acknowledgment in paragraph 3,
# neither the name or logo of this software nor the names of its
# authors may be used to endorse or promote products derived from this
# software without specific prior written permission.  The name of the
# software includes the following terms, and any derivatives thereof:
# "Rocks", "Rocks Clusters", and "Avalanche Installer".  For licensing of 
# the associated name, interested parties should contact Technology 
# Transfer & Intellectual Property Services, University of California, 
# San Diego, 9500 Gilman Drive, Mail Code 0910, La Jolla, CA 92093-0910, 
# Ph: (858) 534-5815, FAX: (858) 534-7345, E-MAIL:invent@ucsd.edu
# 
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS''
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# @Copyright@
#

import string
import os.path
import rocks.commands
import IPy

class command(rocks.commands.Command):
	MustBeRoot = 0
		

	
class Command(command):
	"""
	Reconfigure a frontend to use a new IP address.

	<arg optional='1' type='string' name='net_conf_path'>
	A file containing the network information in a pythoninc format
	The file must contain the following variables: public_ip, 
	netmask, gw, dns, and fqdn.
	</arg>

	<example cmd='reconfigure /root/net_conf.conf'>
	Reconfigure the frontend
	</example>
	"""
	
	def run(self, params, args):

		if len(args) != 1 :
			self.abort('You need to pass the net_conf.conf file as input')

		net_conf_file = args[0]
		if not os.path.isfile(net_conf_file):
			self.abort('The %s path does not point to a valid file' % net_conf_file)

		# get new config values with quick and dirty trick, add the follwing variables:
		# public_ip
		# netmask
		# gw
		# dns
		# fqdn
		# private_mac
		# public_mac
		execfile(net_conf_file, {}, globals())
		ip_temp =  IPy.IP(public_ip + '/' + netmask, make_net=True)
		network_addr = str(ip_temp.net())
		broad_cast = str(ip_temp.broadcast())
		hostname = fqdn.split('.')[0]
		domainname = fqdn[fqdn.find('.') + 1:]


		# get old attribute values before overwriting
		old_fqdn = self.db.getHostAttr('localhost', 'Kickstart_PublicHostname')
		old_hostname = old_fqdn.split('.')[0]
		old_domainname = old_fqdn[old_fqdn.find('.') + 1:]
		old_ip = self.db.getHostAttr('localhost', 'Kickstart_PublicAddress')
		old_broad_cast = self.db.getHostAttr('localhost', 'Kickstart_PublicBroadcast')
		old_gw = self.db.getHostAttr('localhost', 'Kickstart_PublicGateway')
		old_network_addr = self.db.getHostAttr('localhost', 'Kickstart_PublicNetwork')
		old_netmask = self.db.getHostAttr('localhost', 'Kickstart_PublicNetmask')
		fix_private_ip = '10.1.1.1'

		public_interface = self.db.getHostAttr('localhost', 'Kickstart_PublicInterface')
		private_interface = self.db.getHostAttr('localhost', 'Kickstart_PrivateInterface')

		# 
		# first let's fix the attrbutes
		# 
		self.command('set.attr', ['Kickstart_PublicHostname', fqdn])
		self.command('set.attr', ['Kickstart_PublicAddress', public_ip])
		self.command('set.attr', ['Kickstart_PublicBroadcast', broad_cast])
		self.command('set.attr', ['Kickstart_PrivateHostname', hostname])
		self.command('set.attr', ['Info_ClusterName', hostname])
		self.command('set.attr', ['Kickstart_PublicGateway', gw])
		self.command('set.attr', ['Kickstart_PublicNetwork', network_addr])
		self.command('set.attr', ['Kickstart_PublicNetmask', netmask])
		self.command('set.attr', ['Kickstart_PublicDNSDomain', domainname])

		#
		# ------  base roll  ------
		#
		# database-data.xml
		self.command('set.network.subnet', ['public', network_addr])
		self.command('set.network.netmask', ['public', netmask])
		if domainname != old_domainname :
			self.command('set.network.zone', ['public', domainname])
		
		if hostname != old_hostname :
			self.command('set.host.name', [old_hostname, hostname])
		self.command('remove.host.route', [hostname, '0.0.0.0'])
		self.command('add.host.route', [hostname, '0.0.0.0', gw, 'netmask=0.0.0.0'])
		self.command('remove.route', ['0.0.0.0'])
		self.command('add.route', ['0.0.0.0', gw, 'netmask=0.0.0.0'])
		self.command('remove.route', [old_ip])
		self.command('add.route', [public_ip, fix_private_ip, 'netmask=255.255.255.255'])
		self.command('set.host.interface.ip', [hostname, public_interface, public_ip])
		self.command('set.host.interface.name', [hostname, public_interface, hostname])
		if private_mac :
			self.command('set.host.interface.mac', [hostname, private_interface, private_mac])
		if public_mac :
			self.command('set.host.interface.mac', [hostname, public_interface, public_mac])

		# grub-server.xml not fixed in this version
		# ss.xml not fixed
		# ca.xml not fixed

		# dns-server.xml
		os.system('/opt/rocks/bin/rocks report resolv > resolve.conf')
		os.system('hostname ' + hostname)
		self.command('sync.dns', [])

		#needs to do this since rocks sync host network will not work without network :-(
		attrs = self.db.getHostAttrs(hostname)
		os.system('''/opt/rocks/bin/rocks report host dhcpd localhost | /opt/rocks/bin/rocks report script | /bin/bash;
/opt/rocks/bin/rocks report host firewall localhost | /opt/rocks/bin/rocks report script attrs="%s" | /bin/bash;
/opt/rocks/bin/rocks report host interface localhost | /opt/rocks/bin/rocks report script | /bin/bash;
/opt/rocks/bin/rocks report host network localhost | /opt/rocks/bin/rocks report script | /bin/bash;
/opt/rocks/bin/rocks report host route localhost | /opt/rocks/bin/rocks report script | /bin/bash;''' % attrs)
		os.system('/etc/init.d/network start')

		# yum.xml
		os.system('sed -i "s/%s/%s/g" /etc/yum.repos.d/rocks-local.repo' % (old_ip, public_ip))

		# mail-server.xml
		os.system('sed -i "s/%s/%s/g" /etc/postfix/main.cf' % (old_domainname, domainname))
		f = open('/etc/postfix/sender-canonical', 'w')
		f.write('@local @%s\n' % fqdn)
		f.close()
		f = open('/etc/postfix/recipient-canonical', 'w')
		f.write('root@%s root\n' % domainname)
		f.close()
		os.system('/usr/sbin/postmap /etc/postfix/sender-canonical')
		os.system('/usr/sbin/postmap /etc/postfix/recipient-canonical')
		os.system('/etc/init.d/postfix restart')

		# apache.xml
		os.system('sed -i "s/ServerName .*/ServerName %s/g" /etc/httpd/conf.d/rocks.conf' % fqdn)
		os.system('/etc/init.d/httpd restart')

		#
		# end base roll ------
		#

		# web-server roll not fixed in this release
		#
		# ------  ganglia roll  ------
		#
		os.system('sed -i "s/data_source .*/data_source %s localhost:8649/g" /etc/ganglia/gmetad.conf' % 
			hostname)
		os.system('/opt/rocks/bin/rocks report host ganglia gmond localhost > /etc/ganglia/gmond.conf')
		os.system('/sbin/service gmond restart')
		os.system('/sbin/service gmetad restart')

		#
		# ------  sge roll  ------
		#
		if hostname != old_hostname:
			# wipe sge installation
			os.system('/sbin/service sgemaster.%s stop' % old_hostname)
			os.system('/sbin/chkconfig sgemaster.%s off' % old_hostname)
			os.system('rm /etc/init.d/sgemaster.%s' % old_hostname)
			os.system('rm -rf /opt/gridengine/default')
			os.system('sed -i "s/%s/%s/g" /opt/gridengine/util/install_modules/sge_configuration.conf' %
				(old_hostname, hostname))
			sge_reconf='''#!/bin/bash
source /etc/profile.d/sge-binaries.sh
chown -R 400.400 $SGE_ROOT

echo sge root $SGE_ROOT
cd $SGE_ROOT && ./inst_sge -m -auto ./util/install_modules/sge_configuration.conf
/etc/rc.d/init.d/sgemaster.`hostname -s` stop
echo "%s.%s %s %s" > $SGE_ROOT/$SGE_CELL/common/host_aliases

cat default/common/configuration | sed -e "s/reporting=false/reporting=true/g" -e "s/joblog=false/joblog=true/g" > /tmp/sge-default-common-config.conf
mv -f /tmp/sge-default-common-config.conf default/common/configuration
chown 400:400 default/common/configuration

/etc/rc.d/init.d/sgemaster.`hostname -s` start

# add default MPI parallel environments
$SGE_ROOT/bin/$SGE_ARCH/qconf -Ap $SGE_ROOT/mpi/rocks-mpich.template 
$SGE_ROOT/bin/$SGE_ARCH/qconf -Ap $SGE_ROOT/mpi/rocks-mpi.template 
$SGE_ROOT/bin/$SGE_ARCH/qconf -Ap $SGE_ROOT/mpi/rocks-ompi.template 
$SGE_ROOT/bin/$SGE_ARCH/qconf -as `/bin/hostname --fqdn` 
$SGE_ROOT/bin/$SGE_ARCH/qconf -rattr queue pe_list 'make mpich mpi orte' all.q 
/opt/rocks/bin/rocks sync config
'''
			os.system(sge_reconf % (hostname, "local", fqdn, hostname))
			
			
			

