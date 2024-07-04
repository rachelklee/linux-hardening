#!/bin/bash
	mkdir -p output
	echo -n > output/unsecure_packages.txt

install ()
{
	if ! apt install -y $1 2>/dev/null | grep --quiet already; then
		echo $1 | tee -a output/unsecure_packages.txt
	else
		echo $1 not installed | tee -a output/unsecure_packages.txt
	fi
}

install at
install autofs
install acunetix
install binwalk
install cowsay
install dovecot-*
install finger
install ftp
install ftp-cloudfs
install ftp-proxy
install ftp-proxy-doc
install ftp-ssl
install ftp-upload
install ftp.app
install ftpcopy
install ftpd
install ftpd-ssl
install ftpgrab
install ftplib-dev
install ftplib3
install ftpmirror
install ftpsync
install ftpwatch
install inetutils-telnet
install inetutils-telnetd
install inetutils-telnetd
install ldap-utils
install libaa-bin
install libguac-client-telnet0
install libnet-telnet-cisco-perl
install libnet-telnet-perl
install libtelnet-dev
install libtelnet-utils
install libtelnet2
install lighttpd
install mactelnet-client
install mactelnet-server
install maltego
install moon-buggy
install netcat
install netcat-openbsd
install netcat-traditional
install netcat*
install nessus
install nfs-common
install nfs-kernel-server
install nis
install nikto
install openswan
install portmap
install popularity-contest
install putty
install python-zeitgeist
install rails
install rhythmbox-plugin-zeitgeist
install rpcbind
install rsh-client
install rsh-redone-client
install rsh-server
install rsync
install ruby-net-telnet
install sendmail
install sgt-puzzles
install slapd
install sl
install snmp
install snort
install strongswan
install talk
install telnet
install telnet-ssl
install telnetd
install telnetd-ssl
install tftp
install tftpd
install xinetd
install xorg-x11-server-common
install zeitgeist
install zeitgeist-core
install zeitgeist-datahub
