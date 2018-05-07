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

import os.path
import os
import re
import subprocess
import sys
import rocks.commands
import xml.etree.ElementTree
import IPy


class command(rocks.commands.HostArgumentProcessor, rocks.commands.Command):
	MustBeRoot = 0


class Command(command):
	"""
	Reconfigure a frontend to use a new IP address.

	<arg optional='1' type='string' name='vc-out.xml'>
	A file containing the network information in a xml format

	The file should be in the format specified in the README file:
	https://github.com/pragmagrid/pragma_boot/tree/master

	For an example see /root/vc-out.xml.template
	</arg>

	<param type='bool' name='compute'>
	It should be set to true when run on a compute node, by defualt
	is false
	</param>

	<param type='bool' name='computepost'>
	It should be set to true when run on a compute node as one of the
	last init script (compute is on of the first init script while
	computepost is one of the last), by default is false
	computepost currently is only used to fix SGE
	</param>

	<example cmd='reconfigure /root/vc-out.xml'>
	Reconfigure the frontend
	</example>
	"""

	def run(self, params, args):
		print "Running dynip"
		(compute, computepost) = self.fillParams([
			('compute', 'n'),
			('computepost', 'n'),
			])

		compute = self.str2bool(compute)
		computepost = self.str2bool(computepost)

		if len(args) != 1:
			self.abort('You need to pass the vc-out.xml file as input')

		net_conf_file = args[0]
		if not os.path.isfile(net_conf_file):
			self.abort('The %s path does not point to a valid file' % net_conf_file)

		# get new config values
		vc_out_xmlroot = xml.etree.ElementTree.parse(net_conf_file).getroot()

		# authorize ssh key
		ssh_key = vc_out_xmlroot.findall('./key')
		if ssh_key:
			print "Authorizing ssh key"
			f = open('/root/.ssh/authorized_keys', 'a')
			f.write(ssh_key[0].text.strip() + '\n')
			f.close()

		if compute:
			print "Fixing compute node"
			self.fixCompute(vc_out_xmlroot, computepost)
		else:
			print "Fixing frontend"
			self.fixFrontend(vc_out_xmlroot)

	def fix411(self, private_ip, private_network_addr, private_netmask):
		# 411-server.xml
		content = """#
		# 411 Specific Apache configuration.
		# Generated automatically by the 411.xml kickstart node.
		#

		Listen 372
		NameVirtualHost %s:372

		<VirtualHost %s:372>
		Alias /411.d/ "/etc/411.d/"
		Alias /411.d "/etc/411.d"

		<Directory /etc/411.d>
						Options Indexes MultiViews
						IndexOptions FancyIndexing

						AllowOverride None
						Order deny,allow
						Allow from %s/%s
						Allow from 127.0.0.1
						Deny from all
		</Directory>
		</VirtualHost> """
		self.write_file('/etc/httpd/conf.d/411.conf', content % (
			private_ip, private_ip, private_network_addr, private_netmask))

	def fixCompute(self, vc_out_xmlroot, computepost):
		"""fix a compute node network based on the vc-out.xml"""

		xml_node = vc_out_xmlroot.findall('./compute')[0]
		name = xml_node.attrib["name"]
		gw = xml_node.attrib["gw"]
		fe_fqdn = vc_out_xmlroot.findall('./frontend')[0].attrib["fqdn"]

		if not computepost:
			hosts_str = '127.0.0.1\tlocalhost.localdomain localhost\n'
			hosts_str += '%s\t%s\n' % (gw, fe_fqdn)
			shosts = "%s\n" % gw
			for iface in xml_node:
				netmask = iface.attrib["netmask"]
				ip = iface.attrib["ip"]
				mac = iface.attrib["mac"]
				iface_name = self.getIface(mac)
				# write ifcfg up script
				ifup_str = 'DEVICE=%s\nIPADDR=%s\nNETMASK=%s\n' % (iface_name, ip, netmask)
				ifup_str += 'BOOTPROTO=none\nONBOOT=yes\nMTU=1500\n'
				if mac:
					ifup_str += 'HWADDR=%s\n' % mac
				self.write_file('/etc/sysconfig/network-scripts/ifcfg-%s' % iface_name, ifup_str)
				iface_domain = iface.tag
				if iface.tag == 'private':
					iface_domain = "local"
				hosts_str += '%s\t%s.%s %s\n' % (ip, name, iface_domain, name)
				shosts += '%s\n' % ip
			# write resolve.conf
			# in rocks compute node we use the FE as DNS server
			self.write_file('/etc/resolv.conf', 'search local\nnameserver %s\n' % gw)

			# write syconfig/network
			self.write_file('/etc/sysconfig/network',
				'NETWORKING=yes\nHOSTNAME=%s.local\nGATEWAY=%s\n' % (name, gw))

			# write /etc/hosts
			self.write_file('/etc/hosts', hosts_str)

			# write static-routes
			static_str = 'any net 224.0.0.0 netmask 255.255.255.0 dev eth0\n'
			static_str += 'any host 255.255.255.255 dev eth0\n'
			self.write_file('/etc/sysconfig/static-routes', static_str)

			# write shost.equiv
			self.write_file('/etc/ssh/shosts.equiv', shosts)

			# write yum.repo
			fname = '/etc/yum.repos.d/rocks-local.repo'
			content = self.read_file(fname)
			i = content.find("baseurl=")
			repo_str = content[:i]
			repo_str += 'baseurl=http://%s/install/rocks-dist/x86_64\n' % gw
			repo_str += 'enabled = 1\n'
			self.write_file(fname, repo_str)

			# manually set the hostname in case the
			os.system('hostname ' + name)

			# fix __init__.py file
			self.fix_init_file(fe_fqdn)

		elif os.path.exists("/etc/profile.d/sge-binaries.sh"):
			#
			# SGE now running as a last init script
			# I need the network up and running to configure SGE
			#

			# find old FEname
			print "Fixing SGE on compute node"
			old_fe_name = [i for i in os.listdir('/etc/init.d/') if i.startswith('sgeexecd')]
			if len(old_fe_name) != 1:
				os.system('ls /etc/init.d/')
				self.abort('Unable to find old frontend name from sgeexecd script')
			old_fe_name = old_fe_name[0].split('.')[1].strip()

			sge_reconfigure = '''#!/bin/bash
. /etc/profile.d/sge-binaries.sh

oldfename=%s
newfename=%s

chkconfig sgeexecd.$oldfename off
rm -f /etc/init.d/sgeexecd.$oldfename
rm -rf $SGE_ROOT/$SGE_CELL/spool/*

list_files="default/common/settings.sh default/common/settings.csh"
list_files="$list_files default/common/act_qmaster default/common/cluster_name"
list_files="$list_files default/common/sgeexecd util/install_modules/sge_host_config.conf"

for i in $list_files; do
        sed -i "s/$oldfename/$newfename/g" $SGE_ROOT/$i
done

mkdir -p $SGE_ROOT/default/spool/qmaster

# sets the ownership to sge user
chown -R 400.400 $SGE_ROOT

# sets up the execution node 
cd $SGE_ROOT && \
        ./inst_sge -noremote -x -auto \
        ./util/install_modules/sge_host_config.conf
'''
			fe_name = fe_fqdn.split('.')[0]
			print "Previous FE FQDN is ", old_fe_name
			print "New FE FQDN is ", fe_name
			sys.stdout.flush()
			os.system(sge_reconfigure % (old_fe_name, fe_name))

	def fixComputes(self, xml_nodes):
		# remove all the compute nodes
		for host in self.getHostnames(["compute"]):
			self.command('remove.host', [host])
		# reload the database
		rank = 0
		for node_xml in xml_nodes:
			hostname = node_xml.attrib["name"]
			if 'cpus' in node_xml.attrib:
				cpus = node_xml.attrib['cpus']
			else:
				# we can just assume
				cpus = '1'
			self.command('add.host', [hostname, 'cpus=' + cpus, 'membership=compute', 'os=linux', 'rack=0', 'rank=' + str(rank)])

			i = 1
			for iface in node_xml:
				ip = iface.attrib["ip"]
				iface_name = None
				if iface.tag == 'private':
					iface_name = "eth0"
				else:
					iface_name = "eth%i" % i
					i = i + 1
				self.command('add.host.interface', [hostname, iface_name, 'ip=' + iface.attrib["ip"], 'subnet=' + iface.tag])
				self.command('set.host.interface.mac', [hostname, iface_name, iface.attrib['mac']])

			# set the host to boot in OS mode
			self.command('set.host.boot', [hostname, 'action=os'])
			rank += 1

	def fix_init_file(self, fe_fqdn):
		# get original file contents
		fname = "/opt/rocks/lib/python2.7/site-packages/rocks/__init__.py"
		content = self.read_file(fname)

		# write content with new DatabaseHost
		i = content.find("DatabaseHost")
		if i == -1:
			return
		content_new = content[:i] + "DatabaseHost = \"%s\"\n" % fe_fqdn.split('.')[0]
		self.write_file(fname, content_new)

	def fixFrontend(self, vc_out_xmlroot):
		"""fix a frontend based on the vc-out.xml file"""

		print "Getting old host attributes"
		old_config = self.getOldConfig()
		print "Reading vc-out.xml attributes"
		frontend = vc_out_xmlroot.find('./frontend')
		new_config = {}
		try:
			new_config["fqdn"] = frontend.attrib["fqdn"]
			new_config["gw"] = frontend.attrib["gw"]
			new_config["name"] = frontend.attrib["name"]
		except: # is old version
			new_config["fqdn"] = frontend.find("public").attrib["fqdn"]
			new_config["gw"] = frontend.find("public").attrib["gw"]
			new_config["name"] = frontend.find("public").attrib["name"]

		new_config["ifaces"] = self.getInterfaces(frontend, new_config["fqdn"], new_config["gw"], "public")
		pub_iface = new_config["ifaces"]["public"]
		priv_iface = new_config["ifaces"]["private"]

		new_config["dns"] = self.getDns(vc_out_xmlroot.findall('./network/dns'))

		#
		# ------  base roll  ------
		#
		print "Updating host attributes"
		self.fixHostAttrs(new_config)
		print "Updating network"
		self.fixNetwork(new_config, old_config)

		# grub-server.xml not fixed in this version
		# ss.xml not fixed
		# ca.xml not fixed

		# yum.xml
		os.system('sed -i "s/%s/%s/g" /etc/yum.repos.d/rocks-local.repo' % (
			old_config["ifaces"]["public"]["ip"], new_config["ifaces"]["public"]["ip"]))

		# mail-server.xml
		print "Updating mail"
		self.fixMail(old_config["ifaces"]["public"]["domainname"], pub_iface["domainname"], new_config["fqdn"])
		print "Updating NFS"
		self.fixNfs(pub_iface["ip"], pub_iface["subnet"], pub_iface["netmask"])

		# autofs-server.xml
		print "Updating autofs"
		os.system("sed -i 's/%s.local/%s.local/g' /etc/auto.share  /etc/auto.home" %
			(old_config["name"], new_config["name"]))

		self.fix411(priv_iface["ip"], priv_iface["subnet"], priv_iface["netmask"])

		#
		# end base roll ------
		#

		# ------  web-server roll  ------
		print "Updating httpd"
		os.system('sed -i "s/ServerName .*/ServerName %s/g" /etc/httpd/conf.d/rocks.conf' % new_config["fqdn"])
		os.system('/usr/bin/systemctl restart httpd')

		print "Updating ganglia"
		self.fixGanglia(new_config["name"])

		# ------  sge roll  ------
		sge_status = os.system('/opt/rocks/bin/rocks list roll | grep sge | grep yes')
		if old_config["name"] != new_config["name"] and sge_status == 0:
			self.fixSge(old_config["name"], new_config["name"], new_config["fqdn"])

		#
		# adding compute node to the DB
		#

		print "Updating compute nodes"
		xml_nodes = vc_out_xmlroot.findall('./compute/node')
		if xml_nodes:
			self.fixComputes(xml_nodes)

		# sync config
		print "Syncing config"
		self.command('sync.config', [])

	def fixGanglia(self, hostname):
		os.system(
			'sed -i "s/data_source .*/data_source %s localhost:8649/g" /etc/ganglia/gmetad.conf' % hostname)
		os.system(
			'/opt/rocks/bin/rocks report host ganglia gmond localhost > /etc/ganglia/gmond.conf')
		os.system('/usr/bin/systemctl restart gmond')
		os.system('/usr/bin/systemctl restart gmetad')

	def fixMail(self, old_domainname, new_domainname, fqdn):
		# mail-server.xml
		os.system('sed -i "s/%s/%s/g" /etc/postfix/main.cf' % (old_domainname, new_domainname))
		f = open('/etc/postfix/sender-canonical', 'w')
		f.write('@local @%s\n' % fqdn)
		f.close()
		f = open('/etc/postfix/recipient-canonical', 'w')
		f.write('root@%s root\n' % new_domainname)
		f.close()
		os.system('/usr/sbin/postmap /etc/postfix/sender-canonical')
		os.system('/usr/sbin/postmap /etc/postfix/recipient-canonical')
		os.system('/usr/bin/systemctl restart postfix')

	def fixNetwork(self, new_config, old_config):
		if new_config["name"] != old_config["name"]:
			self.command('set.host.name', [old_config["name"], new_config["name"]])
		for iface_name, iface in new_config["ifaces"].items():
			old_iface = None
			if iface_name in old_config["ifaces"]:
				old_iface = old_config["ifaces"][iface_name]
			if old_iface is None:
				self.command('add.network', [iface_name, iface["subnet"], iface["netmask"]])
			else:
				self.command('set.network.subnet', [iface_name, iface["subnet"]])
				self.command('set.network.netmask', [iface_name, iface["netmask"]])
			if iface_name == "public":
				if iface["domainname"] != old_iface["domainname"]:
					self.command('set.network.zone', ['public', iface["domainname"]])
				self.command('remove.host.route', [old_config["name"], 'address=0.0.0.0'])
				self.command('add.host.route', [new_config["name"], '0.0.0.0', iface["gw"], 'netmask=0.0.0.0'])
				self.command('remove.route', ['0.0.0.0'])
				self.command('add.route', ['0.0.0.0', iface["gw"], 'netmask=0.0.0.0'])
				self.command('remove.route', [old_iface["ip"]])
				self.command('add.route',
		                     [iface["ip"], new_config["ifaces"]["private"]["ip"],
		                      'netmask=255.255.255.255'])
			if old_iface is None:
				self.command('add.host.interface', [new_config["name"], iface["iface"]])
				self.command('set.host.interface.subnet', [new_config["name"], iface["iface"], iface_name])
			self.command('set.host.interface.ip',
	                   [new_config["name"], iface["iface"], iface["ip"]])
			self.command('set.host.interface.name',
	                   [new_config["name"], iface["iface"], new_config["name"]])
			self.command('set.host.interface.mac',
	                   [new_config["name"], iface["iface"], iface["mac"]])
	
		sys.stdout.flush()
		os.system('/opt/rocks/bin/rocks report resolv > resolve.conf')
		print "Setting hostname to %s" % new_config["fqdn"]
		os.system('hostname ' + new_config["fqdn"])
		self.command('sync.dns', [])
		# needs to do this since rocks sync host network will not work without network :-(
		attrs = self.db.getHostAttrs(new_config["name"])
		os.system('''/opt/rocks/bin/rocks report host dhcpd localhost | /opt/rocks/bin/rocks report script | /bin/bash;
	/opt/rocks/bin/rocks report host firewall localhost | /opt/rocks/bin/rocks report script attrs="%s" | /bin/bash;
	/opt/rocks/bin/rocks report host interface localhost | /opt/rocks/bin/rocks report script | /bin/bash;
	/opt/rocks/bin/rocks report host network localhost | /opt/rocks/bin/rocks report script | /bin/bash;
	/opt/rocks/bin/rocks report host route localhost | /opt/rocks/bin/rocks report script | /bin/bash;
	/opt/rocks/bin/rocks report host > /etc/hosts;''' % attrs)
		network_status = os.system('systemctl is-active network')
		if network_status == 0:
			print "Restarting network"
			os.system('systemctl restart network')
		else:
			print "Network not yet started; assuming it gets started later"

	def fixNfs(self, private_ip, private_network_addr, private_netmask):
		# nfs-server.xml
		content = '/export %s(rw,async,no_root_squash) %s/%s(rw,async)' % (
		private_ip, private_network_addr, private_netmask)
		self.write_file('/etc/exports', content)
		os.system(' /usr/sbin/exportfs -a')

	def fixHostAttrs(self, new_config):
		#
		# first let's fix the attrbutes
		#
		self.command('set.attr', ['Kickstart_PublicHostname', new_config["fqdn"]])
		self.command('set.attr', ['Kickstart_PublicAddress', new_config["ifaces"]["public"]["ip"]])
		self.command('set.attr', ['Kickstart_PublicBroadcast', new_config["ifaces"]["public"]["broadcast"]])
		self.command('set.attr', ['Kickstart_PrivateHostname', new_config["name"]])
		self.command('set.attr', ['Info_ClusterName', new_config["name"]])
		self.command('set.attr', ['Kickstart_PublicGateway', new_config["gw"]])
		self.command('set.attr', ['Kickstart_PublicNetwork', new_config["ifaces"]["public"]["subnet"]])
		self.command('set.attr', ['Kickstart_PublicNetmask', new_config["ifaces"]["public"]["netmask"]])
		self.command('set.attr', ['Kickstart_PublicDNSDomain', new_config["ifaces"]["public"]["domainname"]])
		self.command('set.attr', ['Kickstart_PublicDNSServers', new_config["dns"]])


	def fixSge(self, old_hostname, hostname, fqdn):
		# wipe sge installation
		os.system('/sbin/service sgemaster.%s stop' % old_hostname)
		os.system('/sbin/chkconfig sgemaster.%s off' % old_hostname)
		os.system('/usr/bin/pkill -9 sge_qmaster; /usr/bin/pkill -9 sge_execd')
		os.system('rm /etc/init.d/sgemaster.%s' % old_hostname)
		os.system('rm -rf /opt/gridengine/default')
		os.system(
			'sed -i "s/%s/%s/g" /opt/gridengine/util/install_modules/sge_configuration.conf' % (
				old_hostname, hostname))
		sge_reconf = '''#!/bin/bash
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

	def getDns(self, dns_nodes):
		dns_servers = ""
		for node_xml in dns_nodes:
			ip = node_xml.attrib['ip']
			if len(dns_servers):
				dns_servers += ",%s" % ip
			else:
				dns_servers += "%s" % ip
		return dns_servers

	def getIface(self, mac):
		try:
			p = subprocess.Popen("ip -o link show| grep %s" % mac, shell=True,
				stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
			iface_out = p.stdout.read()
			iface_part = iface_out.split(" ")[1]
			return iface_part.split(":")[0]
		except Exception as e:
			sys.stderr.write("Error, unable to find iface for mac %s: %s" % (mac, str(e)))
			return None

	def getInterfaces(self, iface_root, fqdn, gw, gw_iface):
		interface_spec = {}
		for interface in iface_root:
			ip = interface.attrib["ip"]
			netmask = interface.attrib["netmask"]
			mac = interface.attrib["mac"]
			mtu = "1500"
			if "mtu" in interface.attrib:
				mtu = interface.attrib["mtu"]
			iface = self.getIface(mac)
			if iface is None:
				print "Unable to find interface for mac %s" % mac
				continue
			print "Found iface %s for mac %s" % (iface, mac)
			interface_spec[interface.tag] = {'ip': ip, 'netmask': netmask, 'mtu': mtu, 'iface': iface, 'mac': mac}
			if interface.tag == gw_iface:
				interface_spec[interface.tag]['gw'] = gw

			ip_temp = IPy.IP(ip + '/' + netmask, make_net=True)
			interface_spec[interface.tag]["subnet"] = str(ip_temp.net())
			interface_spec[interface.tag]["broadcast"] = str(ip_temp.broadcast())
			interface_spec[interface.tag]["domainname"] = fqdn[fqdn.find('.') + 1:]

		return interface_spec

	def getOldConfig(self):
		old_config = {}
		old_config["fqdn"] = self.db.getHostAttr('localhost', 'Kickstart_PublicHostname')
		old_config["name"] = old_config["fqdn"].split('.')[0]
		old_config["ifaces"] = {}
		existing_networks = self.command('list.network', [])
		for line in existing_networks.split("\n")[1:]:
			matcher = re.search("^([^:]+):\s+(\S+)\s+(\S+)", line)
			if matcher:
				(name, subnet, netmask) = matcher.groups()
				old_config["ifaces"][name] = {'subnet': subnet, 'netmask': netmask}
		old_config["ifaces"]["public"]["domainname"] = self.db.getHostAttr('localhost', 'Kickstart_PublicDNSDomain')
		print old_config["ifaces"]["public"]["domainname"]
		old_config["ifaces"]["public"]["ip"] = self.db.getHostAttr('localhost', 'Kickstart_PublicAddress')
		old_config["ifaces"]["public"]["iface"] = self.db.getHostAttr('localhost',
		                                       'Kickstart_PublicInterface')
		old_config["ifaces"]["private"]["iface"] = self.db.getHostAttr('localhost',
		                                        'Kickstart_PrivateInterface')
		return old_config

	def read_file(self, fname):
		"""read the file_name and return its content"""
		f = open(fname, 'r')
		content = f.read()
		f.close()
		return content

	def write_file(self, file_name, content):
		"""write the content in the file_name"""
		f = open(file_name, 'w')
		f.write(content)
		f.close()
