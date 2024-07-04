#!/bin/bash

init ()
{
	mkdir -p output
	truncate -s 0 output/ubuntu_16.04_error.txt
}

report_fail ()
{
	echo $1 : $2 | tee -a output/ubuntu_16.04_error.txt
}

rl_ubuntu_1604_0001()
{
	bashrc_list=( $( find /home/*/.bashrc) )

	for bashrc in ${bashrc_list[@]};
	do
		md5sum=$(md5sum $bashrc |cut -d " " -f 1)
		if [ $md5sum != ef0ece783589187659cb84dc01d689f7 ]; then
			report_fail rl_ubuntu_1604_0001 "${bashrc} md5sum not equal to ef0ece783589187659cb84dc01d689f7"
		fi
	done
	## following rl_ubuntu_1604_0001 for second part of instruction
}

rl_ubuntu_1604_0002 ()
{
	# run check_user.sh
	# folllow game plan
	:
}

rl_ubuntu_1604_0003 ()
{
	# run check_suspicious_program.sh
	# follow game plan
	:
}

rl_ubuntu_1604_0004 ()
{
	# run check_hacked_packages.sh
	# follow game plan
	:
}

rl_ubuntu_1604_0005 ()
{
	# run check_hiddenmedia.sh
	# follow game plan
	:
}


rl_ubuntu_1604_0006 ()
{
	if dpkg -s unattended-upgrades > /dev/null 2>&1 ; then
		:
	else
		report_fail rl_ubuntu_1604_0006 "package unattended-upgrades is not installed : sudo apt install -y unattended-upgrades"
	fi
	# follow game plan
}

rl_ubuntu_1604_0007 ()
{
	# follow game plan
	:
}

rl_ubuntu_1604_0013 ()
{
	# install secure package
	if dpkg -s apparmor > /dev/null 2>&1 ; then
		:
	else
		report_fail rl_ubuntu_1604_0013 "package aparmor is not installed : sudo apt install -y apparmor"
	fi

	if dpkg -s auditd > /dev/null 2>&1; then
		:
	else
		report_fail rl_ubuntu_1604_0013 "package auditd is not installed : sudo apt install -y auditd"
	fi

	if dpkg -s binutils > /dev/null 2>&1; then
		:
	else
		report_fail rl_ubuntu_1604_0013 "package binutils is not installed : sudo apt install -y binutils"
	fi

	if dpkg -s chkrootkit > /dev/null 2>&1; then
		:
	else
		report_fail rl_ubuntu_1604_0013 "package chkrootkit is not installed : sudo apt install -y chkrootkit"
	fi

	if dpkg -s clamav > /dev/null 2>&1; then
		:
	else
		report_fail rl_ubuntu_1604_0013 "package clamav is not installed : sudo apt install -y clamav"
	fi

	if dpkg -s file > /dev/null 2>&1; then
		:
	else
		report_fail rl_ubuntu_1604_0013 "package file is not installed : sudo apt install -y file"
	fi

	if dpkg -s gufw > /dev/null 2>&1; then
		:
	else
		report_fail rl_ubuntu_1604_0013 "package gufw is not installed : sudo apt install -y gufw"
	fi
	
	if dpkg -s iptables > /dev/null 2>&1; then
		:
	else
		report_fail rl_ubuntu_1604_0013 "package iptables is not installed : sudo apt install -y iptables"
	fi

	if dpkg -s libpam-cracklib > /dev/null 2>&1; then
		:
	else
		report_fail rl_ubuntu_1604_0013 "package libpam-cracklib is not installed : sudo apt install -y libpam-cracklib"
	fi

	if dpkg -s libpam-pwquality > /dev/null 2>&1; then
		:
	else
		report_fail rl_ubuntu_1604_0013 "package libpam-pwquality is not installed : sudo apt install -y libpam-pwquality"
	fi

	if dpkg -s ntp > /dev/null 2>&1; then
		:
	else
		report_fail rl_ubuntu_1604_0013 "package ntp is not installed : sudo apt install -y ntp"
	fi

	if dpkg -s psad > /dev/null 2>&1; then
		:
	else
		report_fail rl_ubuntu_1604_0013 "package psad is not installed : sudo apt install -y psad"
	fi

	if dpkg -s rkhunter > /dev/null 2>&1; then
		:
	else
		report_fail rl_ubuntu_1604_0013 "package rkhunter is not installed : sudo apt install -y rkhunter"
	fi

	if dpkg -s tcpd > /dev/null 2>&1; then
		:
	else
		report_fail rl_ubuntu_1604_0013 "package tcpd is not installed : sudo apt install -y tcpd"
	fi

	if dpkg -s screen > /dev/null 2>&1; then
		:
	else
		report_fail rl_ubuntu_1604_0013 "package screen is not installed : sudo apt install -y screen"
	fi

	if dpkg -s cron > /dev/null 2>&1; then
		:
	else
		report_fail rl_ubuntu_1604_0013 "package cron is not installed : sudo apt install -y cron"
	fi

	if dpkg -s members > /dev/null 2>&1; then
		:
	else
		report_fail rl_ubuntu_1604_0013 "package members is not installed : sudo apt install -y members"
	fi

	if dpkg -s logrotate > /dev/null 2>&1; then
		:
	else
		report_fail rl_ubuntu_1604_0013 "package logrotate is not installed : sudo apt install -y logrotate"
	fi

	if dpkg -s libpam-modules-bin > /dev/null 2>&1; then
		:
	else
		report_fail rl_ubuntu_1604_0013 " package libpam-modules-bin is not-installed : sudo apt install -y libpam-modules-bin"
	fi
}

rl_ubuntu_1604_0014 ()
{
	# disable login for root
	root_line=$(grep ^root:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]* /etc/passwd |cut -d : -f 1-7)
	root_username=$(echo $root_line | cut -d : -f 1)
	root_hash=$(echo $root_line | cut -d : -f 2)
	root_uid=$(echo $root_line | cut -d : -f 3)
	root_gid=$(echo $root_line | cut -d : -f 4)
	root_comment=$(echo $root_line | cut -d : -f 5)
	root_home=$(echo $root_line | cut -d : -f 6)
	root_shell=$(echo $root_line | cut -d : -f 7)

	# root hash has to be x
	if [ "$root_hash" != "x" ]; then
		report_fail rl_ubuntu_1604_0014 "root password hash is not x, modify like root:x:0:0:::/root:/bin/bash in /etc/passwd"
	fi

	# root uid has to be 0
	if [ "$root_uid" != "0" ]; then
		report_fail rl_ubuntu_1604_0014 "root uid is not 0, modify like root:x:0:0:::/root:/bin/bash in /etc/passwd"
	fi

	# root gid has to be 0
	if [ "$root_gid" != "0" ]; then
		report_fail rl_ubuntu_1604_0014 "root gid is not 0, modify like root:x:0:0:::/root:/bin/bash in /etc/passwd"
	fi

	# root home has to be /root
	if [ "$root_home" != "/root" ]; then
		report_fail rl_ubuntu_1604_0014 "root home is not /root, modify like root:x:0:0:::/root:/bin/bash in /etc/passwd"
	fi

	# root shell has to be /bin/bash
	if [ "$root_shell" != "/bin/bash" ]; then
		report_fail rl_ubuntu_1604_0014 "root shell is not /bin/bash, modify like root:x:0:0:::/root:/bin/bash in /etc/passwd"
	fi

}

rl_ubuntu_1604_0016 ()
{
	# follow game plan
	:
}

rl_ubuntu_1604_0017 ()
{
	# follow game plan
	:
}

rl_ubuntu_1604_0018 ()
{
	# check home directory permission
	home_directory_list=( $(ls /home) )
	for home_directory in ${home_directory_list[@]};
	do
		home_directory_permission=$(stat -c "%a" /home/$home_directory)
		
		if [ "$home_directory_permission" != "750" ]; then
			report_fail rl_ubuntu_1604_0018 "/home/${home_directory} permission is not 0750 : sudo chmod -s /home/${home_directory}; sudo chmod 0750 /home/${home_directory}"
		fi
	done

	# check the owner of home directory
	user_homedir_list=( $(grep -v /usr/sbin/nologin /etc/passwd |grep -v /bin/false |cut -d : -f 1,6) )
	
	for user_homedir in ${user_homedir_list[@]};
	do
		this_user=$( echo $user_homedir | cut -d : -f 1)
		this_homedir=$( echo $user_homedir | cut -d : -f 2)
		this_user_group=$( groups $this_user | cut -d : -f 2 | cut -d " " -f 2)

		if [ -d "$this_homedir" ]; then	
			owner=$(stat -c "%U" $this_homedir)
			owner_group=$(stat -c "%G" $this_homedir)
			echo $this_user has $this_homedir owner is $owner:$owner_group
			if [ "$this_user" != "$owner" ]; then
				report_fail rl_ubuntu_1604_0018 "$this_user does not own $this_homedir : sudo chown $this_user:$this_user_group $this_homedir"
			elif [ "$this_user_group" != "$owner_group" ]; then
				report_fail rl_ubuntu_1604_0018 "$this_user does not own $this_homedir : sudo chown $this_user:$this_user_group $this_homedir"
			fi
		else
			report_fail rl_ubuntu_1604_0018 "$this_user home directory $this_homedir not exist : sudo /sbin/mkhomedir_helper $this_user"
		fi
	done
}

rl_ubuntu_1604_0019 ()
{
	# follow game plan
	:
}

rl_ubuntu_1604_0020 ()
{
	# follow game plan
	:
}

rl_ubuntu_1604_0023 ()
{
	# follow game plan
	:
}

rl_ubuntu_1604_0025 ()
{
	# this need some fix
	:
}

rl_ubuntu_1604_0026 ()
{
	# this need some fix
	:
}

rl_ubuntu_1604_0027 ()
{
	# Remove file with no owner
	file_no_owner_list=($( find / -nouser 2>/dev/null) )

	for file_no_owner in ${file_no_owner_list[@]};
	do
		report_fail rl_ubuntu_1604_0027 "change owner to root : sudo chown root $file_no_owner"
	done

	file_no_group_list=($( find / -nogroup 2>/dev/null) )

	for file_no_group in ${file_no_group_list[@]};
	do
		report_fail rl_ubuntu_1604_0027 "change group to root : sudo chgrp root $file_no_group"
	done
}

rl_ubuntu_1604_0028 ()
{
	# Disable prelink
	if dpkg -s prelink > /dev/null 2>&1 ; then
		report_fail rl_ubuntu_1604_0028 "prelink is installed, remove it : sudo apt autoremove --purge -y prelink"
	fi
}

rl_ubuntu_1604_0029 ()
{
	# Encure no legacy "+" entries exists in /etc/passwd
	bad_line_list=( $( grep "^+:" /etc/passwd ) )
	
	for bad_line in ${bad_line_list[@]};
	do
		report_fail rl_ubuntu_1604_0029 "Legacy + entries exists in /etc/passwd : remove $bad_line from /etc/passwd"
	done
}

rl_ubuntu_1604_0032 ()
{
	# Ensure no user have .forward file
	user_homedir_list=( $(grep -v /usr/sbin/nologin /etc/passwd |grep -v /bin/false |cut -d : -f 1,6) )

	for user_homedir in ${user_homedir_list[@]};
	do
		this_user=$( echo $user_homedir | cut -d : -f 1)
		this_homedir=$( echo $user_homedir | cut -d : -f 2)

		if [ ! -h "$this_homedir/.forward" -a -f "$this_homedir/.forward" ]; then
			report_fail rl_ubuntu_1604_0032 "$this_user have .forward at $this_homedir : sudo rm $this_homedir/.forward"
		fi
	done
}

rl_ubuntu_1604_0033 ()
{
	# Ensure no user have .netrc files
	user_homedir_list=( $(grep -v /usr/sbin/nologin /etc/passwd |grep -v /bin/false |cut -d : -f 1,6) )

	for user_homedir in ${user_homedir_list[@]};
	do
		this_user=$( echo $user_homedir | cut -d : -f 1)
		this_homedir=$( echo $user_homedir | cut -d : -f 2)

		if [ ! -h "$this_homedir/.netrc" -a -f "$this_homedir/.netrc" ]; then
			report_fail rl_ubuntu_1604_0033 "$this_user have .netrc at $this_homedir : sudo rm $this_homedir/.netrc"
		fi
	done
}

rl_ubuntu_1604_0034 ()
{
	# Ensure no user have .rhosts files
	user_homedir_list=( $(grep -v /usr/sbin/nologin /etc/passwd |grep -v /bin/false |cut -d : -f 1,6) )

	for user_homedir in ${user_homedir_list[@]};
	do
		this_user=$( echo $user_homedir | cut -d : -f 1)
		this_homedir=$( echo $user_homedir | cut -d : -f 2)

		if [ ! -h "$this_homedir/.rhosts" -a -f "$this_homedir/.rhosts" ]; then
			report_fail rl_ubuntu_1604_0034 "$this_user have .rhosts at $this_homedir : sudo rm $this_homedir/.rhosts"
		fi
	done
}
rl_ubuntu_1604_0035 ()
{
       # Ensure all groups in /etc/passwd exist in /etc/group
	for i in $(cut -s -d : -f4 /etc/passwd | sort -u );
	do
		grep -q -P "^.*?:[^:]*:$i:" /etc/group

		if [ $? -ne 0 ];
		then
			new_group="group_$RANDOM"
			grep -q "^$new_group:" /etc/group
			while [ $? -eq 0 ]
			do
				new_group="group_$RANDOM"
				grep -q "^$new_group:" /etc/group
			done
			report_fail rl_ubuntu_1604_0035 "Group $i is referenced by /etc/passwd but does not exist in /etc/group : sudo groupadd $new_group -g $i"
		fi
	done
}

# ensure no duplicate GIDs exits
rl_ubuntu_1604_0037()
{
#	cat /etc/group | cut -s -d : -f 3 | sort -n | uniq -c | while read x; do
#		[ -z "${x}" ] && break
#		set - $x
#		if [ $1 -gt 1 ]; then
#			groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
#			echo "Duplicate GID ($2): ${groups}"
#		fi
#	done

	duplicate_gid_list=( $(cut -s -d : -f 3 /etc/group | sort -n | uniq -d) )

	duplicate_group_gid_list=()
	for duplicate_gid in ${duplicate_gid_list[@]}; do
		duplicate_group_gid_list+=( $( grep [^:]*:[^:]*:$duplicate_gid:[^:]* /etc/group | cut -d : -f 1,3 ) )
	done

	new_gid=1000
	for duplicate_group_gid in ${duplicate_group_gid_list[@]}; do

		duplicate_group=$(echo $duplicate_group_gid | cut -d : -f 1)
		duplicate_gid=$(echo $duplicate_group_gid | cut -d : -f 2)
		while [ $new_gid -lt 65536 ]; do
			new_gid=$[$new_gid+1]
			cut -s -d : -f 3 /etc/group | grep $new_gid || break
		done
		report_fail rl_ubuntu_1604_0036 "duplicate gid $duplicate_gid in /etc/group : sudo groupmod -g $new_gid $duplicate_group"
	done
}

# ensure no duplicate UIDs exist
rl_ubuntu_1604_0036()
{
#	cat /etc/passwd | cut -d : -f 3 | sort -n | uniq -c | while read x; do 
#		[ -z "${x}" ] && break
#		set - $x
#		if [ $1 -gt 1 ]; then
#			users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
#			echo "Duplicate UID ($2) : ${users}"
#		fi
#	done

	duplicate_uid_list=( $(cut -s -d : -f 3 /etc/passwd | sort -n | uniq -d) )
	echo ${duplicate_uid_list[*]}

	duplicate_user_uid_list=()
	for duplicate_uid in ${duplicate_uid_list[@]}; do
		duplicate_user_uid_list+=( $( grep [^:]*:[^:]*:$duplicate_uid:[^:]*:[^:]*:[^:]*:[^:]* /etc/passwd | cut -d : -f 1,3 ) )
	done
	echo ${duplicate_user_uid_list[*]}

	new_uid=1000
	for duplicate_user_uid in ${duplicate_user_uid_list[@]}; do

		duplicate_user=$(echo $duplicate_user_uid | cut -d : -f 1)
		duplicate_uid=$(echo $duplicate_user_uid | cut -d : -f 2)
		while [ $new_uid -lt 65536 ]; do
			new_uid=$[$new_uid+1]
			cut -s -d : -f 3 /etc/passwd | grep $new_uid || break
		done
		report_fail rl_ubuntu_1604_0036 "duplicate uid $duplicate_uid in /etc/passwd : sudo usermod -u $new_uid $duplicate_user"
	done
}

rl_ubuntu_1604_0124 ()
{
	#Ensure no duplicate user names exist
	cat /etc/passwd | cut -f 1 -d : | sort -n | uniq -c | while read x; do
		[ -z "${x}" ] && break
		set - $x
		if [ $1 -gt 1 ]; then
			uids=`awk -F: '($1 == n) {print $3}' n=$2 /etc/passwd | xargs`
			report_fail rl_ubuntu_1604_0124 "Duplicate User Name ($2): ${uids} : remove duplicates in /etc/passwd"
		fi
	done
}

rl_ubuntu_1604_0038 ()
{
	# Ensure no duplicate group names exist
	cat /etc/group | cut -f 1 -d : | sort -n |uniq -c | while read x ; do
		[ -z "${x}" ] && break
		set - $x
		if [ $1 -gt 1 ]; then
			gids =`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs `
			report_fail rl_ubuntu_1604_0038 "Duplicate Group Name ($2) : ${gids}"
		fi
	done
}

rl_ubuntu_1604_0039 ()
{
	# Ensure shadow group is empty
	if grep ^shadow:[^:]*:[^:]*:[^:] /etc/group; then
		shadow_line=$(grep ^shadow: /etc/group)
		new_shadow_line=$(echo $shadow_line | cut -d : -f 1-3)
		report_fail rl_ubuntu_1604_0039 "shadow group is not empty : replace \"$shadow_line\" with \"$new_shadow_line:\" in /etc/group"
	fi

	shadow_gid=$(grep ^shadow: /etc/group | cut -d : -f 3)
	
	user_gid_list=( $(cut -d : -f 1,4 /etc/passwd) )

	for user_gid in ${user_gid_list[@]};
	do
		user=$(echo $user_gid | cut -d : -f 1)
		gid=$(echo $user_gid | cut -d : -f 2)
		shadow_line=$(grep $user:[^:]*:[^:]*:$gid: /etc/passwd)
		if [ $gid == $shadow_gid ]; then
			report_fail rl_ubuntu_1604_0039 "shadow group is not empty : fix or remove \"$shadow_line\" in /etc/passwd"
		fi
	done
}

rl_ubuntu_1604_0125 ()
{
	# Install aide
	if dpkg -s aide > /dev/null 2>&1; then
		if ! grep "0 5 \* \* \* \/usr\/bin\/aide --check" /etc/crontab > /dev/null; then
			report_fail rl_ubuntu_1604_0125 'aid did not setup crontab  : add "0 5 \* \* \* /usr/bin/aide --check" to/etc/crontab'
		fi
	else
		report_fail rl_ubuntu_1604_0125 "package aide is not installed : sudo apt install -y aide"
	fi

}

rl_ubuntu_1604_0041 ()
{
	if ! grep "SUBSYSTEM==\"usb\", ENV{UDISKS_AUTO}=\"0\"" /etc/udev/rules.d/85-no-automount.rules > /dev/null; then
		report_fail rl_ubuntu_1604_0041 "autofs not harden : sudo echo SUBSYSTEM==\\\"usb\\\", ENV{UDISKS_AUTO}=\\\"0\\\" | sudo tee /etc/udev/rules.d/85-no-automount.rules"
	fi
}

rl_ubuntu_1604_0042 ()
{
	if dpkg -s avahi-daemon > /dev/null 2>&1; then
		if ! systemctl is-enabled avahi-daemon | grep -e disabled -e masked; then
			report_fail rl_ubuntu_1604_0042 "avahi-daemon is not disabled : sudo systemctl disable avahi-daemon"
		fi

		if ! systemctl is-active avahi-daemon | grep inactive; then
			report_fail rl_ubuntu_1604_0042 "avahi-daemon is not inactive : sudo systemctl stop avahi-daemon"
		fi

		if ! grep manual /etc/init/avahi-daemon.override > /dev/null 2>&1; then
			report_fail rl_ubuntu_1604_0042 "avahi not harden : sudo echo manual | sudo tee /etc/init/avahi-daemon.override"
		fi
	fi
}

rl_ubuntu_1604_0043 ()
{
	if dpkg -s cups > /dev/null 2>&1; then
		if ! systemctl is-enabled cups | grep -e disabled -e masked ; then
			report_fail rl_ubuntu_1604_0043 "cups is not disabled : sudo systemctl disable cups"
		fi

		if ! systemctl is-active cups | grep inactive; then
			report_fail rl_ubuntu_1604_0043 "cups is not inactive : sudo systemctl stop cups"
		fi

		if ! grep manual /etc/init/cups.override > /dev/null; then
			report_fail rl_ubuntu_1604_0043 "cups not harden : sudo echo manual | sudo tee /etc/init/cups.override"
		fi
	fi
}

rl_ubuntu_1604_0044 ()
{
	if dpkg -s ModemManager > /dev/null 2>&1; then
		if ! systemctl is-enabled ModemManager | grep -e disabled -e masked; then
			report_fail rl_ubuntu_1604_0044 "ModemManager is not disabled : sudo systemctl disable ModemManager"
		fi

		if ! systemctl is-active ModemManager | grep inactive; then
			report_fail rl_ubuntu_1604_0044 "ModemManager is not inactive : sudo systemctl stop ModemManager"
		fi

		if ! grep manual /etc/init/ModemManager.override > /dev/null; then
			report_fail rl_ubuntu_1604_0044 "cups not harden : sudo echo manual | sudo tee /etc/init/ModemManager.override"
		fi
	fi
}

rl_ubuntu_1604_0045 ()
{
	if dpkg -s whoopsie > /dev/null 2>&1; then
		if ! systemctl is-enabled whoopsie | grep -e disabled -e masked; then
			report_fail rl_ubuntu_1604_0045 "whoopsie is not disabled : sudo systemctl disable whoopsie"
		fi

		if ! systemctl is-active whoopsie | grep inactive; then
			report_fail rl_ubuntu_1604_0045 "whoopsie is not inactive : sudo systemctl stop whoopsie"
		fi

		if ! grep manual /etc/init/whoopsie.override > /dev/null; then
			report_fail rl_ubuntu_1604_0045 "whoopsie not harden : sudo echo report_crashes=false | sudo tee /etc/default/whoopsie"
		fi
	fi
}

rl_ubuntu_1604_0046 ()
{
	if dpkg -s apport > /dev/null 2>&1; then
		if ! systemctl is-enabled apport | grep -e disabled -e masked; then
			report_fail rl_ubuntu_1604_0046 "apport is not disabled : sudo systemctl mask apport"
		fi

		if ! systemctl is-active apport | grep inactive; then
			report_fail rl_ubuntu_1604_0046 "apport is not inactive : sudo systemctl stop apport"
		fi

		if ! grep "enable=0" /etc/default/apport > /dev/null; then
			report_fail rl_ubuntu_1604_0046 "apport is not hardened : echo enable=0 | sudo tee /etc/default/apport"
		fi
	fi
}

rl_ubuntu_1604_0047 ()
{
	if ! grep "ENABLED=\"0\"" /etc/default/irqbalance > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0047 "irqbalance is not hardened : echo ENABLED=\\\"0\\\" | sudo tee /etc/default/irqbalance"
	fi
}

rl_ubuntu_1604_0048 ()
{
	# fs.protected_hardlinks = 1
	if ! grep 1 /proc/sys/fs/protected_hardlinks > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "fs.protected_hardlinks = 1 not in /etc/sysctl.conf : echo fs.protected_hardlinks = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# fs.protected_symlinks = 1
	if ! grep 1 /proc/sys/fs/protected_symlinks > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "fs.protected_symlinks = 1 not in /etc/sysctl.conf : echo fs.protected_symlinks = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.ip_forward = 0
	if ! grep 0 /proc/sys/net/ipv4/ip_forward > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.ip_forward = 0 not in /etc/sysctl.conf : echo net.ipv4.ip_forward = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.conf.all.rp_filter = 1
	if ! grep 1 /proc/sys/net/ipv4/conf/all/rp_filter > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.conf.all.rp_filter = 1 not in /etc/sysctl.conf : echo net.ipv4.conf.all.rp_filter = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.conf.default.rp_filter = 1
	if ! grep 1 /proc/sys/net/ipv4/conf/default/rp_filter > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.conf.default.rp_filter = 1 not in /etc/sysctl.conf : echo net.ipv4.conf.default.rp_filter = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.icmp_echo_ignore_broadcasts = 1
	if ! grep 1 /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.icmp_echo_ignore_broadcasts = 1 not in /etc/sysctl.conf : echo net.ipv4.icmp_echo_ignore_broadcasts = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.conf.all.accept_source_route = 0
	if ! grep 0 /proc/sys/net/ipv4/conf/all/accept_source_route > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.conf.all.accept_source_route = 0 not in /etc/sysctl.conf : echo net.ipv4.conf.all.accept_source_route = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv6.conf.all.accept_source_route = 0
	if ! grep 0 /proc/sys/net/ipv6/conf/all/accept_source_route > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv6.conf.all.accept_source_route = 0 not in /etc/sysctl.conf : echo net.ipv6.conf.all.accept_source_route = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.conf.default.accept_source_route = 0
	if ! grep 0 /proc/sys/net/ipv4/conf/default/accept_source_route > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.conf.default.accept_source_route = 0 not in /etc/sysctl.conf : echo net.ipv4.conf.default.accept_source_route = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv6.conf.default.accept_source_route = 0
	if ! grep 0 /proc/sys/net/ipv6/conf/default/accept_source_route > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv6.conf.default.accept_source_route = 0 not in /etc/sysctl.conf : echo net.ipv6.conf.default.accept_source_route = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.conf.all.send_redirects = 0
	if ! grep 0 /proc/sys/net/ipv4/conf/all/send_redirects > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.conf.all.send_redirects = 0 not in /etc/sysctl.conf : echo net.ipv4.conf.all.send_redirects = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.conf.default.send_redirects = 0
	if ! grep 0 /proc/sys/net/ipv4/conf/default/send_redirects > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.conf.default.send_redirects = 0 not in /etc/sysctl.conf : echo net.ipv4.conf.default.send_redirects = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.tcp_keepalive_time = 300
	if ! grep 300 /proc/sys/net/ipv4/tcp_keepalive_time > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.tcp_keepalive_time = 300 not in /etc/sysctl.conf : echo net.ipv4.tcp_keepalive_time = 300 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.tcp_keepalive_probes = 5
	if ! grep 5 /proc/sys/net/ipv4/tcp_keepalive_probes > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.tcp_keepalive_probes = 5 not in /etc/sysctl.conf : echo net.ipv4.tcp_keepalive_probes = 5 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.tcp_keepalive_intvl = 15
	if ! grep 15 /proc/sys/net/ipv4/tcp_keepalive_intvl > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.tcp_keepalive_intvl = 15 not in /etc/sysctl.conf : echo net.ipv4.tcp_keepalive_intvl = 15 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.tcp_max_syn_backlog = 2048
	if ! grep 2048 /proc/sys/net/ipv4/tcp_max_syn_backlog > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.tcp_max_syn_backlog = 2048 not in /etc/sysctl.conf : echo net.ipv4.tcp_max_syn_backlog = 2048 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.tcp_syncookies = 1
	if ! grep 1 /proc/sys/net/ipv4/tcp_syncookies > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.tcp_syncookies = 1 not in /etc/sysctl.conf : echo net.ipv4.tcp_syncookies = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.tcp_synack_retries = 2
	if ! grep 2 /proc/sys/net/ipv4/tcp_synack_retries > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.tcp_synack_retries = 2 not in /etc/sysctl.conf : echo net.ipv4.tcp_synack_retries = 2 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.tcp_syn_retries = 5
	if ! grep 5 /proc/sys/net/ipv4/tcp_syn_retries > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.tcp_syn_retries = 5 not in /etc/sysctl.conf : echo net.ipv4.tcp_syn_retries = 5 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.conf.all.log_martians = 1
	if ! grep 1 /proc/sys/net/ipv4/conf/all/log_martians > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.conf.all.log_martians = 1 not in /etc/sysctl.conf : echo net.ipv4.conf.all.log_martians = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.icmp_ignore_bogus_error_responses = 1
	if ! grep 1 /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.icmp_ignore_bogus_error_responses = 1 not in /etc/sysctl.conf : echo net.ipv4.icmp_ignore_bogus_error_responses = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.conf.all.accept_redirects = 0
	if ! grep 0 /proc/sys/net/ipv4/conf/all/accept_redirects > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.conf.all.accept_redirects = 0 not in /etc/sysctl.conf : echo net.ipv4.conf.all.accept_redirects = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv6.conf.all.accept_redirects = 0
	if ! grep 0 /proc/sys/net/ipv6/conf/all/accept_redirects > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv6.conf.all.accept_redirects = 0 not in /etc/sysctl.conf : echo net.ipv6.conf.all.accept_redirects = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.conf.default.accept_redirects = 0
	if ! grep 0 /proc/sys/net/ipv4/conf/default/accept_redirects > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.conf.default.accept_redirects = 0 not in /etc/sysctl.conf : echo net.ipv4.conf.default.accept_redirects = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv6.conf.default.accept_redirects = 0
	if ! grep 0 /proc/sys/net/ipv6/conf/default/accept_redirects > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv6.conf.default.accept_redirects = 0 not in /etc/sysctl.conf : echo net.ipv6.conf.default.accept_redirects = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.icmp_echo_ignore_all = 1
	if ! grep 1 /proc/sys/net/ipv4/icmp_echo_ignore_all > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.icmp_echo_ignore_all = 1 not in /etc/sysctl.conf : echo net.ipv4.icmp_echo_ignore_all = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.conf.all.secure_redirects = 0
	if ! grep 0 /proc/sys/net/ipv4/conf/all/secure_redirects > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.conf.all.secure_redirects = 0 not in /etc/sysctl.conf : echo net.ipv4.conf.all.secure_redirects = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv4.conf.default.secure_redirects = 0
	if ! grep 0 /proc/sys/net/ipv4/conf/default/secure_redirects > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv4.conf.default.secure_redirects = 0 not in /etc/sysctl.conf : echo net.ipv4.conf.default.secure_redirects = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv6.conf.default.router_solicitations = 0
	if ! grep 0 /proc/sys/net/ipv6/conf/default/router_solicitations > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv6.conf.default.router_solicitations = 0 not in /etc/sysctl.conf : echo net.ipv6.conf.default.router_solicitations = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv6.conf.default.accept_ra_rtr_pref = 0
	if ! grep 0 /proc/sys/net/ipv6/conf/default/accept_ra_rtr_pref > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv6.conf.default.accept_ra_rtr_pref = 0 not in /etc/sysctl.conf : echo net.ipv6.conf.default.accept_ra_rtr_pref = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv6.conf.default.accept_ra_pinfo = 0
	if ! grep 0 /proc/sys/net/ipv6/conf/default/accept_ra_pinfo > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv6.conf.default.accept_ra_pinfo = 0 not in /etc/sysctl.conf : echo net.ipv6.conf.default.accept_ra_pinfo = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv6.conf.default.accept_ra_defrtr = 0
	if ! grep 0 /proc/sys/net/ipv6/conf/default/accept_ra_defrtr > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv6.conf.default.accept_ra_defrtr = 0 not in /etc/sysctl.conf : echo net.ipv6.conf.default.accept_ra_defrtr = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv6.conf.default.secure_redirects = 0
	if ! grep 0 /proc/sys/net/ipv6/conf/default/secure_redirects > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv6.conf.default.secure_redirects = 0 not in /etc/sysctl.conf : echo net.ipv6.conf.default.secure_redirects = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv6.conf.all.accept_ra = 0
	if ! grep 0 /proc/sys/net/ipv6/conf/all/accept_ra > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv6.conf.all.accept_ra = 0 not in /etc/sysctl.conf : echo net.ipv6.conf.all.accept_ra = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv6.default.accept_ra = 0
	if ! grep 0 /proc/sys/net/ipv6/default/accept_ra > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv6.default.accept_ra = 0 not in /etc/sysctl.conf : echo net.ipv6.default.accept_ra = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv6.conf.default.autoconf = 0
	if ! grep 0 /proc/sys/net/ipv6/conf/default/autoconf > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv6.conf.default.autoconf = 0 not in /etc/sysctl.conf : echo net.ipv6.conf.default.autoconf = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv6.conf.default.dad_transmits = 0
	if ! grep 0 /proc/sys/net/ipv6/conf/default/dad_transmits > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv6.conf.default.dad_transmits = 0 not in /etc/sysctl.conf : echo net.ipv6.conf.default.dad_transmits = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv6.conf.default.max_addresses = 1
	if ! grep 1 /proc/sys/net/ipv6/conf/default/max_addresses > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv6.conf.default.max_addresses = 1 not in /etc/sysctl.conf : echo net.ipv6.conf.default.max_addresses = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv6.conf.all.disable_ipv6 = 1
	if ! grep 1 /proc/sys/net/ipv6/conf/all/disable_ipv6 > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv6.conf.all.disable_ipv6 = 1 not in /etc/sysctl.conf : echo net.ipv6.conf.all.disable_ipv6 = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv6.conf.default.disable_ipv6 = 1
	if ! grep 1 /proc/sys/net/ipv6/conf/default/disable_ipv6 > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv6.conf.default.disable_ipv6 = 1 not in /etc/sysctl.conf : echo net.ipv6.conf.default.disable_ipv6 = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# net.ipv6.conf.lo.disable_ipv6 = 1
	if ! grep 1 /proc/sys/net/ipv6/conf/lo/disable_ipv6 > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "net.ipv6.conf.lo.disable_ipv6 = 1 not in /etc/sysctl.conf : echo net.ipv6.conf.lo.disable_ipv6 = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.acc = 4
	if ! grep 4 /proc/sys/kernel/acc > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.acc = 4 not in /etc/sysctl.conf : echo kernel.acc = 4 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.acpi_video_flags = 0
	if ! grep 0 /proc/sys/kernel/acpi_video_flags > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.acpi_video_flags = 0 not in /etc/sysctl.conf : echo kernel.acpi_video_flags = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.auto_msgmni = 0
	if ! grep 0 /proc/sys/kernel/auto_msgmni > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.auto_msgmni = 0 not in /etc/sysctl.conf : echo kernel.auto_msgmni = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.bootloader_type = 114
	if ! grep 114 /proc/sys/kernel/bootloader_type > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.bootloader_type = 114 not in /etc/sysctl.conf : echo kernel.bootloader_type = 114 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.bootloader_version = 2
	if ! grep 2 /proc/sys/kernel/bootloader_version > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.bootloader_version = 2 not in /etc/sysctl.conf : echo kernel.bootloader_version = 2 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.cad_pid = 1
	if ! grep 1 /proc/sys/kernel/cad_pid > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.cad_pid = 1 not in /etc/sysctl.conf : echo kernel.cad_pid = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.cap_last_cap = 37
	if ! grep 37 /proc/sys/kernel/cap_last_cap > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.cap_last_cap = 37 not in /etc/sysctl.conf : echo kernel.cap_last_cap = 37 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.compat-log = 1
	if ! grep 1 /proc/sys/kernel/compat-log > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.compat-log = 1 not in /etc/sysctl.conf : echo kernel.compat-log = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.core_pipe_limit = 0
	if ! grep 0 /proc/sys/kernel/core_pipe_limit > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.core_pipe_limit = 0 not in /etc/sysctl.conf : echo kernel.core_pipe_limit = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.core_uses_pid = 1
	if ! grep 1 /proc/sys/kernel/core_uses_pid > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.core_uses_pid = 1 not in /etc/sysctl.conf : echo kernel.core_uses_pid = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.ctrl-alt-del = 0
	if ! grep 0 /proc/sys/kernel/ctrl-alt-del > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.ctrl-alt-del = 0 not in /etc/sysctl.conf : echo kernel.ctrl-alt-del = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.dmesg_restrict = 1
	if ! grep 1 /proc/sys/kernel/dmesg_restrict > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.dmesg_restrict = 1 not in /etc/sysctl.conf : echo kernel.dmesg_restrict = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.exec-shield = 1
	if ! grep 1 /proc/sys/kernel/exec-shield > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.exec-shield = 1 not in /etc/sysctl.conf : echo kernel.exec-shield = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.ftrace_dump_on_oops = 0
	if ! grep 0 /proc/sys/kernel/ftrace_dump_on_oops > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.ftrace_dump_on_oops = 0 not in /etc/sysctl.conf : echo kernel.ftrace_dump_on_oops = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.ftrace_enabled = 1
	if ! grep 1 /proc/sys/kernel/ftrace_enabled > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.ftrace_enabled = 1 not in /etc/sysctl.conf : echo kernel.ftrace_enabled = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.hardlockup_all_cpu_backtrace = 0
	if ! grep 0 /proc/sys/kernel/hardlockup_all_cpu_backtrace > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.hardlockup_all_cpu_backtrace = 0 not in /etc/sysctl.conf : echo kernel.hardlockup_all_cpu_backtrace = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.hardlockup_panic = 0
	if ! grep 0 /proc/sys/kernel/hardlockup_panic > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.hardlockup_panic = 0 not in /etc/sysctl.conf : echo kernel.hardlockup_panic = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.msgmnb = 65536
	if ! grep 65536 /proc/sys/kernel/msgmnb > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.msgmnb = 65536 not in /etc/sysctl.conf : echo kernel.msgmnb = 65536 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.msgmax = 65536
	if ! grep 65536 /proc/sys/kernel/msgmax > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.msgmax = 65536 not in /etc/sysctl.conf : echo kernel.msgmax = 65536 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.kptr_restrict = 2
	if ! grep 2 /proc/sys/kernel/kptr_restrict > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.kptr_restrict = 2 not in /etc/sysctl.conf : echo kernel.kptr_restrict = 2 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.panic = 30
	if ! grep 30 /proc/sys/kernel/panic > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.panic = 30 not in /etc/sysctl.conf : echo kernel.panic = 30 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.panic_on_oops = 30
	if ! grep 30 /proc/sys/kernel/panic_on_oops > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.panic_on_oops = 30 not in /etc/sysctl.conf : echo kernel.panic_on_oops = 30 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.randomize_va_space = 2
	if ! grep 2 /proc/sys/kernel/randomize_va_space > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.randomize_va_space = 2 not in /etc/sysctl.conf : echo kernel.randomize_va_space = 2 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.shmmax = 68719476736
	if ! grep 68719476736 /proc/sys/kernel/shmmax > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.shmmax = 68719476736 not in /etc/sysctl.conf : echo kernel.shmmax = 68719476736 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.shmall = 4294967296
	if ! grep 4294967296 /proc/sys/kernel/shmall > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.shmall = 4294967296 not in /etc/sysctl.conf : echo kernel.shmall = 4294967296 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# kernel.sysrq = 0
	if ! grep 0 /proc/sys/kernel/sysrq > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "kernel.sysrq = 0 not in /etc/sysctl.conf : echo kernel.sysrq = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# fs.suid_dumpable = 0
	if ! grep 0 /proc/sys/fs/suid_dumpable > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "fs.suid_dumpable = 0 not in /etc/sysctl.conf : echo fs.suid_dumpable = 0 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# vm.dirty_background_ratio = 10
	if ! grep 10 /proc/sys/vm/dirty_background_ratio > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "vm.dirty_background_ratio = 10 not in /etc/sysctl.conf : echo vm.dirty_background_ratio = 10 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# vm.panic_on_oom = 1
	if ! grep 1 /proc/sys/vm/panic_on_oom > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "vm.panic_on_oom = 1 not in /etc/sysctl.conf : echo vm.panic_on_oom = 1 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

	# vm.swappiness = 100
	if ! grep 100 /proc/sys/vm/swappiness > /dev/null 2>&1; then
		report_fail rl_ubuntu_1604_0048 "vm.swappiness = 100 not in /etc/sysctl.conf : echo vm.swappiness = 100 | sudo tee -a /etc/sysctl.conf; sudo sysctl -p"
	fi

}

rl_ubuntu_1604_0049 ()
{
	# Harden lightdm
	unity_greeter=()

	lightdm_file_list=( $(grep -lr greeter-show-remote-login /usr/share/lightdm/lightdm.conf.d/ ) )
	if [ -z $lightdm_file_list ]; then
		unity_greeter+=("greeter-show-remote-login=false")
	else
		for lightdm_file in ${lightdm_file_list[@]};
		do
			if ! grep -q "greeter-show-remote-login=false" $lightdm_file; then
				report_fail rl_ubunu_1604_0049 "greeter-show-remote-login=false missing from $lightdm_file"
			fi
		done
	fi

	lightdm_file_list=( $(grep -lr allow-guest /usr/share/lightdm/lightdm.conf.d/ ) )
	
	if [ -z $lightdm_file_list ]; then
		unity_greeter+=("allow-guest=false")
	else
		for lightdm_file in ${lightdm_file_list[@]};
		do
			if ! grep -q "allow-guest=false" $lightdm_file; then
				report_fail rl_ubunu_1604_0049 "allow-guest=false missing from $lightdm_file"
			fi
		done
	fi

	lightdm_file_list=( $(grep -lr greeter-hide-user-list /usr/share/lightdm/lightdm.conf.d/ ) )
	
	if [ -z $lightdm_file_list ]; then
		unity_greeter+=("greeter-hide-user-list=true")
	else
		for lightdm_file in ${lightdm_file_list[@]};
		do
			if ! grep -q "greeter-hide-user-list=true" $lightdm_file; then
				report_fail rl_ubunu_1604_0049 "greeter-hide-user-list=true missing from $lightdm_file"
			fi
		done
	fi

	lightdm_file_list=( $(grep -lr greeter-show-manual-login /usr/share/lightdm/lightdm.conf.d/ ) )
	
	if [ -z $lightdm_file_list ]; then
		unity_greeter+=("greeter-show-manual-login=true")
	else
		for lightdm_file in ${lightdm_file_list[@]};
		do
			if ! grep -q "greeter-show-manual-login=true" $lightdm_file; then
				report_fail rl_ubunu_1604_0049 "greeter-show-manual-login=true missing from $lightdm_file"
			fi
		done
	fi

	if [ ! -z $unity_greeter ]; then
		unity_greeter_line=""
		
		report_fail rl_ubuntu_1604_0049 "echo [Seat:*] | sudo tee /usr/share/lightdm/lightdm.conf.d/50-unity-greeter.conf"

		for line in ${unity_greeter[@]};
		do
			report_fail rl_ubuntu_1604_0049 "echo $line | sudo tee -a /usr/share/lightdm/lightdm.conf.d/50-unity-greeter.conf"
		done
	fi

}

rl_ubuntu_1604_0051 ()
{
	# /etc/pam.d/su
	bad_line=$(grep "auth" /etc/pam.d/su | grep "sufficient" | grep "pam_permit.so" )
	if [ ! -z "$bad_line"  ]; then
		report_fail rl_ubuntu_1605_0049 "\"$bad_line\" exist in /etc/pam.d/su, remove the line"
	fi
}

init
#rl_ubuntu_1604_0001
#rl_ubuntu_1604_0002
#rl_ubuntu_1604_0006
#rl_ubuntu_1604_0013
#rl_ubuntu_1604_0014
#rl_ubuntu_1604_0018
#rl_ubuntu_1604_0027
#rl_ubuntu_1604_0028
#rl_ubuntu_1604_0029
#rl_ubuntu_1604_0032
#rl_ubuntu_1604_0033
#rl_ubuntu_1604_0034
#rl_ubuntu_1604_0035
#rl_ubuntu_1604_0036
#rl_ubuntu_1604_0037
#rl_ubuntu_1604_0124
#rl_ubuntu_1604_0038
#rl_ubuntu_1604_0039
#rl_ubuntu_1604_0125
#rl_ubuntu_1604_0041
rl_ubuntu_1604_0042
rl_ubuntu_1604_0043
rl_ubuntu_1604_0044
rl_ubuntu_1604_0045
rl_ubuntu_1604_0046
rl_ubuntu_1604_0047
rl_ubuntu_1604_0048
rl_ubuntu_1604_0049
rl_ubuntu_1604_0051
