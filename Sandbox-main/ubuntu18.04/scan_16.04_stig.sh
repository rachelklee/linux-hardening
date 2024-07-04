#!/bin/bash

clear_file ()
{
	mkdir -p output
	echo -n > output/ubuntu_16.04_error.txt
}

report_fail ()
{
	echo $1 : $2 | tee -a output/ubuntu_16.04_error.txt
}

SV-90069r1_rule ()
{
	if [ ! -f /etc/lsb-release ]; then
		report_fail SV-90069r1_rule nofile
	else
		if ! grep --quiet "^DISTRIB_RELEASE=16.04" /etc/lsb-release; then
			report_fail SV-90069r1_rule fail1
		fi

		if ! grep --quiet "^DISTRIB_CODENAME=xenial" /etc/lsb-release; then
			report_fail SV-90069r1_rule fail2
		fi

		if ! grep --quiet "^DISTRIB_RELEASE=16.04.5 LTS" /etc/lsb-release; then
			report_fail SV-90069r1_rule fail3
		fi
	fi
}

SV-90071r4_rule ()
{
	if ! /usr/lib/update-notifier/apt-check --human-readable | grep --quiet "0 updates are security updates" ; then
		report_fail SV-90071r4_rule fail	
	fi
}

SV-90073r2_rule ()
{
	if [ ! -f /etc/dconf/db/local.d/01-banner-message ]; then
		report_fail SV-90073r2_rule nofile
	else
		if ! grep --quiet "^banner-message-enable=true" /etc/dconf/db/local.d/01-banner-message; then
			report_fail SV-90073r2_rule fail
		fi
	fi
}

SV-90115r2_rule ()
{
	if ! cat /etc/issue | grep --quiet "^You are accessing a U.S. Government (USG) Information Sistem (IS) that is provided for USG-authorized us only." ; then
		report_fail SV-90115r2_rule fail
	fi
}

#SV-90117r3_rule ()
#{
	
#}

SV-90199r2_rule ()
{
	if ! dpkg -l | grep --quiet "vlock                                      2.2.2" ; then
		report_fail SV-90199r2_rule fail
	fi
}

SV-90121r2_rule ()
{
	if [ ! -f /etc/profile.d/autologout.sh ]; then
		report_fail SV-90121r2_rule nofile
	else
		if ! grep --quiet "^TMOUT=900" /etc/profile.d/autologout.sh; then
			report_fail SV-90121r2_rule fail1
		elif ! grep --quiet "^readonly TMOUT" /etc/profile.d/autologout.sh; then
			report_fail SV-90121r2_rule fail2
		elif ! grep --quiet "^export TMOUT" /etc/profile.d/autologout.sh; then
			report_fail SV-90121r2_rule fail3
		fi
	fi
}

SV-90123r2_rule ()
{
	if [ ! -f /etc/security/limits.conf ]; then
		report_fail SV-90123r2_rule nofile
	else
		if ! grep --quiet "^\* hard maxlogins 10" /etc/security/limits.conf; then
			report_fail SV-90123r2_rule fail		
		fi
	fi
}

SV-90125r3_rule ()
{
	if ! passwd -S | grep --quiet "^root L"; then
		report_fail SV-90125r3_rule fail
	fi
}

SV-90129r2_rule ()
{
	if [ ! -f /etc/security/pwquality.conf ]; then
		report_fail SV-90129r2_rule nofile
	else
		if ! grep --quiet "^ucredit = -1" /etc/security/pwquality.conf; then
			report_fail SV-90129r2_rule fail
		fi
	fi
}

SV-90131r2_rule ()
{
	if [ ! -f /etc/security/pwquality.conf ]; then
		report_fail SV-90131r2_rule nofile
	else
		if ! grep --quiet "^lcredit = -1" /etc/security/pwquality.conf; then
			report_fail SV-90131r2_rule fail
		fi
	fi
}

SV-90133r2_rule ()
{
	if [ ! -f /etc/security/pwquality.conf ]; then
		report_fail SV-90133r2_rule nofile
	else
		if ! grep --quiet "^dcredit = -1" /etc/security/pwquality.conf; then
			report_fail SV-90133r2_rule fail
		fi
	fi
}

SV-90135r2_rule ()
{
	if [ ! -f /etc/security/pwquality.conf ]; then
		report_fail SV-90135r2_rule nofile
	else
		if ! grep --quiet "^ocredit = -1" /etc/security/pwquality.conf; then
			report_fail SV-90135r2_rule fail
		fi
	fi
}

SV-90137r2_rule ()
{
	if [ ! -f /etc/security/pwquality.conf ]; then
		report_fail SV-90137r2_rule nofile
	else
		if ! grep --quiet "^difok = 8" /etc/security/pwquality.conf; then
			report_fail SV-90137r2_rule fail
		fi
	fi
}

SV-90139r2_rule ()
{
	if [ ! -f /etc/login.defs ]; then
		report_fail SV-90139r2_rule nofile
	else
		if ! grep --quiet "^ENCRYPT_METHOD SHA512" /etc/login.defs; then
			report_fail SV-90139r2_rule fail
		fi
	fi
}

SV-90143r2_rule ()
{
	if [ ! -f /etc/pam.d/common-password ]; then
		report_fail SV-90143r2_rule nofile
	else
		if ! grep "^password" /etc/pam.d/common-password | grep --quiet "rounds=5000" ; then
			report_fail SV-90143r2_rule fail
		fi
	fi
## insert password  [success=1 default=ignore]  pam_unix.so obscure sha512 rounds=5000
}

SV-90145r2_rule ()
{
	if [ ! -f /etc/pam.d/common-password ]; then
		report_fail SV-90145r2_rule nofile
	else
		if ! grep "^password" /etc/pam.d/common-password | grep --quiet "sha512" ; then 
			report_fail SV-90145r2_rule fail
		fi
	fi
}

SV-90149r1_rule ()
{
	if ! sudo chage -l root | grep --quiet "^Password expires					: never" ; then
		report_fail SV-90149r1_rule fail
	fi
}

SV-90151r2_rule ()
{
	if [ ! -f /etc/login.defs ]; then
		report_fail SV-90151r2_rule nofile
	#else
		##AFA SCORES PASS_MIN_DAYS	7##
		#if ! grep --quiet "^PASS_MIN_DAYS	1" /etc/login.defs; then
		#	report_fail SV-90151r2_rule fail
		#fi
	fi
}

SV-90153r2_rule ()
{
	if [ ! -f /etc/login.defs ]; then
		report_fail SV-90153r2_rule nofile
	#else
		##AFA SCORES PASS_MAX_DAYS	90##
		#if ! grep --quiet "^PASS_MAX_DAYS	60" /etc/login.defs; then
		#	report_fail SV-90153r2_rule fail
		#fi
	fi
}

SV-90155r2_rule ()
{
	if [ ! -f /etc/pam.d/common-password ]; then
		report_fail SV-90155r2_rule nofile
	else
		if ! grep "^password" /etc/pam.d/common-password | grep --quiet "remember=5" ; then
			report_fail SV-90155r2_rule fail
		fi
	fi
##insert password [success=1 default=ignore]      pam_unix.so obscure sha512 remember=5 rounds=5000
}

SV-90157r2_rule ()
{
	if [ ! -f /etc/security/pwquality.conf ]; then
		report_fail SV-90157r2_rule nofile
	else
		if ! grep --quiet "^minlen = 15" /etc/security/pwquality.conf; then
			report_fail SV-90157r2_rule fail
		fi
	fi
}

SV-90159r2_rule ()
{
	if [ ! -f /etc/pam.d/\* ]; then
		report_fail SV-90159r2_rule nofile
	else
		if grep --quiet "nullok" /etc/pam.d/*; then
			report_fail SV-90159r2_rule fail
		fi
	fi
}

SV-90161r2_rule ()
{
	if [ ! -f /etc/security/pwquality.conf ]; then
		report_fail SV-90161r2_rule nofile
	else
		if ! grep --quiet "^dictcheck = 1" /etc/security/pwquality.conf; then
			report_fail SV-90161r2_rule fail
		fi
	fi
}

SV-90163r1_rule ()
{
	if [ ! -f /etc/pam.d/passwd ]; then
		report_fail SV-90163r1_rule nofile
	else
		if ! grep --quiet "^@include common-password" /etc/pam.d/passwd; then
			report_fail SV-90163r2_rule fail
		fi
	fi
}

SV-90165r3_rule ()
{
	if [ ! -f /etc/default/useradd ]; then
		report_fail SV-90165r3_rule nofile
	else
		if ! grep --quiet "^INACTIVE=35" /etc/default/useradd; then
			report_fail SV-90163r2_rule fail
		fi
	fi
}

SV-90167r2_rule ()
{
	if [ ! -f /etc/pam.d/common-auth ]; then
		report_fail SV-90165r3_rule nofile
	else
		if ! grep "auth" | grep --quiet "onner=fail deny=3" ; then
			report_fail SV-90167r2_rule fail
		fi
	fi
}

SV-90169r2_rule ()
{
	if [ ! -f /etc/sudoers ]; then
		report_fail SV-90169r2_rule nofile
	else
		if grep "NOPASSWD" /etc/sudoers; then
			report_fail SV-90169r2_rule fail1
		elif grep "!authenticate" /etc/sudoers; then
			report_fail SV-90169r2_rule fail2
		fi
	fi
}

SV-90173r1_rule ()
{
	if [ ! -f /etc/pam.d/common-auth ]; then
		report_fail SV-90173r1_rule nofile
	else
		if ! grep "^auth" /etc/pam.d/common-auth | grep --quiet "pam_faildelay.so delay=4000000" ; then
			report_fail SV-90173r1_rule fail
		fi
	fi
##insert auth required pam_faildelay.so delay=4000000
}

# SV-90175r2_rule ()
# {
# 	if [ ! -f /etc/gdm3/custom.conf ]; then
# 		report_fail SV-90175r2_rule nofile
# 	else
# 		if ! grep --quiet "AutomaticLoginEnable = false" /etc/gdm3/custom.conf; then
# 			report_fail SV-90175r2_rule fail
# 		fi
# 	fi	
# }

SV-90177r1_rule ()
{
	if [ ! -f /etc/pam.d/login ]; then
		report_fail SV-90177r1_rule nofile
	else
		if ! grep --quiet "^session required pam_lastlog.so showfailed" /etc/pam.d/login; then
			report_fail SV-90177r1_rule fail
		fi
	fi
##insert session required pam_lastlog.so showfailed
}

SV-90179r1_rule ()
{
	if find / -name '*.shosts' 2>&1 | grep -v "Permission denied" | grep --quiet '*.shosts' ; then
		report_fail SV-90179r1_rule fail
	fi
}

SV-90181r2_rule ()
{
	if find / -name '*shosts.equiv' 2>&1 | grep -v "Permission denied" | grep --quiet '*shosts.equiv' ; then
		report_fail SV-90181r2_rule fail
	fi
}

# SV-90191r2_rule ()
# {
# 	if [ ! -f /proc/sys/crypto/fips_enabled ]; then
# 		report_fail SV-90191r2_rule nofile
# 	else
# 		if ! grep -i 1 /proc/sys/crypto/fips_enabled | grep --quiet 1; then
# 			report_fail SV-90191r2_rule fail
# 		fi
# 	fi
# }
# 
SV-90185r2_rule ()
{
	if [ ! -f /boot/grub/grub.cfg ]; then
		report_fail SV-90185r2_rule nofile
	else
		if ! grep -i password /boot/grub/grub.cfg | grep --quiet "^password_pbkdf2 root" ; then
			report_fail SV-90185r2_rule fail
		fi
	fi
}

SV-90187r2_rule ()
{
	if find / -type d -perm -0002 -not -user root 2>&1 | grep -v "Permission denied" | grep --quiet ".*" ; then
		report_fail SV-90187r2_rule fail
	fi
}

SV-90193r3_rule ()
{
	if find / -type d -perm -0002 -not -group root 2>&1 | grep -v "Permission denied" | grep --quiet ".*" ; then
		report_fail SV-90193r3_rule fail
	fi
}

SV-90195r3_rule ()
{
	if ! apt list aide 2>&1 | grep -v "WARNING" | grep --quiet "aide/xenial 0.16~a2.git20130520-3 amd64" ; then
		report_fail SV-90195r3_rule fail
	fi
}

SV-90197r2_rule ()
{
	if [ ! -f /etc/cron.daily/aide ]; then
		report_fail SV-90197r2_rule nofile
	else	
		if ! ls -al /etc/cron.daily/aide | grep --quiet "\-rwxr\-xr\-x" ; then
			report_fail SV-90197r2_rule fail
		fi
	fi
}

SV-90199r3_rule ()
{
	if [ ! -f /etc/aide/aide.conf ]; then
		report_fail SV-90199r3_rule nofile
	else
		if ! grep --quiet "VarFile = OwnerMode+n+l+X+acl" /etc/aide/aide.conf; then
			report_fail SV-90199r3_rule fail
		fi
	fi
}

SV-90201r1_rule ()
{
	if ! dpkg -l | grep aide | grep --quiet "ii  aide                                       0.16~a2.git20130520-3" ; then
	report_fail SV-90201r1_rule
	elif ! dpkg -l | grep aide | grep --quiet "ii  aide-common                                0.16~a2.git20130520-3" ; then
	report_fail SV-90201r1_rule
	fi
}

SV-90203r3_rule ()
{
	if [ ! -f /etc/default/aide ]; then
		report_fail SV-90203r1_rule nofile
	else
		if ! grep --quiet "^SILENTREPORTS=no" /etc/default/aide; then
			report_fail SV-90203r1_rule fail
		fi
	fi
}

SV-90205r2_rule ()
{
	if [ ! -f /etc/default/aide ]; then
		report_fail nofile
	else
		if ! grep --quiet "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattr+sha512" /etc/default/aide; then
			report_fail SV-90205r2_rule fail1
		fi
		if ! grep --quiet "/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattr+sha512" /etc/default/aide; then
			report_fail SV-90205r2_rule fail2
		fi
		if ! grep --quiet "/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattr+sha512" /etc/default/aide; then
			report_fail SV-90205r2_rule fail3
		fi
		if ! grep --quiet "/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattr+sha512" /etc/default/aide; then
			report_fail SV-90205r2_rule fail4
		fi
		if ! grep --quiet "/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattr+sha512" /etc/default/aide; then
			report_fail SV-90205r2_rule fail5
		fi
		if ! grep --quiet "/usr/sbin/audispd p+i+n+u+g+s+b+acl+xattr+sha512" /etc/default/aide; then
			report_fail SV-90205r2_rule fail6
		fi
		if ! grep --quiet "/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattr+sha512" /etc/default/aide; then
			report_fail SV-90205r2_rule fail7
		fi
	fi
}

SV-90207r2_rule ()
{
	if ! grep --quiet "APT::Get::AllowUnauthenticated \"false\";" /etc/apt/apt.conf.d/01-vendor-ubuntu ; then
		report_fail SV-90207r2_rule fail
	fi
}

SV-90209r1_rule ()
{
	if ! grep --quiet "Unattended-Upgrade::Remove-Unused-Dependencies \"true\";" /etc/apt/apt.conf.d/50unattended-upgrades ; then
		report_fail SV-90209r1_rule fail
	fi
}

SV-90211r2_rule ()
{
	if [ ! -f /etc/modprobe.d/usb-storage.conf ]; then
		report_fail SV-90211r2_rule nofile
	else	
		if ! grep --quiet "install usb-storage /bin/true" /etc/modprobe.d/usb-storage.conf ; then
			report_fail SV-90211r2_rule fail
		fi
	fi
}

SV-90213r2_rule ()
{
	if ! systemctl status autofs | grep --quiet "Active: active (running)" ; then
		report_fail SV90213r2_rule fail
	fi
}

SV-90215r2_rule ()
{
	if ! sudo apparmor_status | grep --quiet "0 profiles are in complain mode." ; then
		report_fail SV-90215r2_rule fail
	fi
}

SV-90221r2_rule ()
{
	if [ ! -f /etc/dconf/db/local.d/00-disable-CAD ]; then
		report_fail SV-90221r2_rule nofile
	else
		if ! grep --quiet "[org/gnome/settings-daemon/plugins/media-keys]" /etc/dconf/db/local.d/00-disable-CAD; then
			report_fail SV-90221r2_rule fail1
		fi
		if ! grep --quiet "logout=\"" /etc/dconf/db/local.d/00-disable-CAD; then
			report_fail SV-90221r2_rule fail2
		fi
	fi
}

SV-90223r2_rule ()
{
	if [ ! -f /etc/login.defs ]; then
		report_fail SV-90223r2_rule nofile
	else
		if ! grep --quiet "UMASK 077" /etc/login.defs; then
			report_fail SV-90223r2_rule fail
		fi
	fi
}

SV-90225r2_rule ()
{
	report_fail SV-90225r2_rule check_stig
}

SV-90227r2_rule ()
{
	report_fail SV-90227r2_rule check_stig
}

SV-90229r1_rule ()
{
	if awk -F: '$3 == 0 {print $1}' /etc/passwd | grep -v --quiet "root" ; then
		report_fail SV-90229r1_rule fail
	fi
}

SV-90231r1_rule ()
{
	report_fail SV-90231r1_rule check_stig
}

SV-90233r2_rule ()
{
	if [ ! -f /etc/pam.d/common-auth ]; then
		report_fail SV-90233r2_rule nofile
	else
		if ! grep --quiet "timestamp_timeout = 86400" /etc/pam.d/common-auth; then
			report_fail SV-90233r2_rule fail
		fi
	fi
}

SV-90235r1_rule ()
{
	if find / -nouser 2>&1 | grep --quiet "*"; then
		report_fail SV-90235r1_rule fail
	fi
}

SV-90237r1_rule ()
{
	if find / -nogroup 2>&1 | grep --quiet "*"; then
		report_fail SV-90237r1_rule
	fi
}

SV-90239r1_rule ()
{
	report_fail SV-90239r1_rule check_stig
}

SV-90241r1_rule ()
{
	if [ ! -f /etc/login.defs ]; then
		report_fail SV-90241r1_rule nofile
	else
		if ! grep --quiet "CREATE_HOME yes" /etc/login.defs; then
			report_fail SV-90241r1_rule fail
		fi
	fi
}

SV-90243r1_rule ()
{
	if ! ls -ld $(awk -F: '($3>=1000)&&($1!="nobody"){print $6}' /etc/passwd) | grep --quiet "^drwxr-xr-x" ; then
		report_fail SV-90243r1_rule fail
	fi
}

SV-90245r1_rule ()
{
	for dirname in /home/* ; do
		if [ $(stat -c "%a" $dirname) -gt 750 ]; then
			report_fail SV-90245r1_rule fail_$dirname
		fi
	done
}

SV-90247r1_rule ()
{
	for dirname in /home/* ; do
		if ! stat -c "%G" $dirname | grep --quiet users; then
			report_fail SV090247r1_rule fail_$dirname	
		fi
	done
}

SV-90249r1_rule ()
{
	for filename in /home/*/.* ; do
		if [ $(stat -c "%a" $filename) -gt 0740 ]; then
			report_fail SV-90249r1_rule fail_$filename
		fi
	done
}

SV-90251r1_rule ()
{
	report_fail SV-90251r1_rule check_stig	
}

SV-90253r1_rule ()
{
	report_fail SV-90253r1_rule check_stig
}

SV-90255r2_rule ()
{
	if awk -F: '($3>=1000)&&($1!="nobody"){print $1,$3,$6}' /etc/passwd | cut -d " " -f3 | grep /etc/fstab ; then
		report_fail SV-90255r2_rule fail
	fi
}

SV-90263r2_rule ()
{
	if ! sudo find / -xdev -perm -002 -type d -fstype xfs -exec ls -lLd {} \; | cut -d " " -f3 | grep --quiet "root" ; then
			report_fail SV-90263r2_rule fail
		fi
}

SV-90265r1_rule ()
{
	if ! systemctl status kdump.service | grep --quiet "Active: inactive (dead)" ; then
		report_fail SV-90265r1_rule fail
	fi
}

SV-90267r2_rule ()
{
	if awk -F: '($3>=1000)&&($1!="nobody"){print $1,$3,$6}' /etc/passwd | cut -d " " -f3  | grep --quiet /etc/fstab ; then
		report_fail SV-90267r2_rule fail
	fi
}

SV-90269r1_rule ()
{
	if grep /var /etc/fstab | grep "UUID=*" ; then
		report_fail SV-90269r1_rule fail
	fi
}

SV-90271r1_rule ()
{
	if grep /var/log/audit /etc/fstab | grep "UUID=*" ; then
		report_fail SV-90271r1_rule fail
	fi
}

SV-90273r2_rule ()
{
	if ! ls -lad /var/log | cut -d ' ' -f4 | grep --quiet syslog ; then
		report_fail SV-90273r2_rule fail
	fi
}

SV-90275r2_rule ()
{
	if ! stat -c "%a" /var/log | grep --quiet "770" ; then
		report_fail SV-90275r2_rule fail
	fi
## run sudo chmod 770 /var/log
}

SV-90279r2_rule ()
{
	if !  ls -la /var/log/syslog | cut -d' ' -f4 | grep --quiet "^adm" ; then
		report_fail SV-90279r2_rule fail
	fi
}

SV-90281r2_rule ()
{
	if ! ls -la /var/log/syslog | cut -d ' ' -f3 | grep --quiet "^syslog" ; then
		report_fail SV-90281r2_rule fail
	fi
}

SV-90283r3_rule ()
{
	if ! stat -c "%a" /var/log/syslog | grep --quiet "^640" ; then
		report_fail SV-90283r3_rule fail
	fi
}

SV-90285r2_rule ()
{
	if sudo find /lib /lib64 /usr/lib -perm /022 -type f | xargs ls -la | grep --quiet "*" ; then
		report_fail SV-90285r3_rule fail
	fi
}

SV-90287r2_rule ()
{
	if sudo find /lib /usr/lib /lib64 ! -user root | xargs ls -la | grep --quiet "*" ; then
		report_fail SV-90287r2_rule fail
	fi
}

SV-90289r2_rule ()
{
	if find /lib /usr/lib /lib64 ! -group root | xargs ls -la | grep --quiet "*" ; then
		report_fail SV-90289r2_rule fail
	fi
}

SV-90291r2_rule ()
{
	if find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 | xargs ls -la 2>/dev/null | grep --quiet "*" ; then
		report_fail SV-90291r2_rule fail
	fi
}

SV-90293r2_rule ()
{
	if sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root | xargs ls -la 2>&1 | grep --quiet "*" ; then
		report_fail SV-90293r2_rule fail
	fi
}

SV-90295r2_rule ()
{
	if sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root | xargs ls -la | grep --quiet "*" ; then
		report_fail SV-90295r2_rule fail
	fi
}

SV-90297r1_rule ()
{
	if ! dpkg -l | grep --quiet auditd ; then
		report_fail SV-90297r1_rule nopackage ;
	else
		if ! systemctl is-active auditd.service | grep --quiet "^active" ; then
			report_fail SV-90297r1_rule fail
		fi
	fi
}

SV-90301r2_rule ()
{
	if [ ! -f /etc/audit/auditd.conf ] ; then
		report_fail SV-90301r2_rule nofile
	else
		if ! grep --quiet "^log_file = /var/log/audit/audit.log" /etc/audit/auditd.conf ; then
			report_fail SV-90301r2_rule fail1
		fi
	fi

	if ! sudo df -h /var/log/audit/ 2>/dev/null | grep --quiet "" ; then
		report_fail SV-90301r2_rule fail2
	fi
}

SV-90305r2_rule ()
{
	if [ ! -f /etc/audit/auditd.conf ] ; then
		report_fail SV-90305r2_rule nofile
	else
		if ! grep --quiet "^action_mail_acct = root" /etc/audit/auditd.conf ; then
			report_fail SV-90305r2_rule fail
		fi
	fi
}


SV-90307r1_rule ()
{
	if [ ! -f /etc/audit/auditd.conf ] ; then
		report_fail SV-90307r1_rule nofile
	else
		if ! grep --quiet "^max_log_file_action = SYSLOG" /etc/audit/auditd.conf ; then
			report_fail SV-90307r1_rule fail
		fi
	fi
}

SV-90309r2_rule ()
{
	if [ ! -f /etc/audit/auditd.conf ] ; then
		report_fail SV-90309r2_rule nofile
	else
		if ! grep --quiet "^disk_full_action = HALT" /etc/audit/auditd.conf ; then
			report_fail SV-90309r2_rule fail
		fi
	fi
}

SV-90311r1_rule ()
{
	if [ ! -f /etc/audisp/audisp-remote.conf ] ; then
		report_fail SV-90311r1_rule nofile
	else
		if ! grep --quiet "^disk_full_action = single" /etc/audisp/audisp-remote.conf ; then
			report_fail SV-90311r1_rule fail
		fi
	fi
}

SV-90313r1_rule ()
{
	if [ ! -f /etc/audisp/audisp-remote.conf ] ; then
		report_fail SV-90311r1_rule nofile
	else
		if ! grep --quiet "^enable_krb5 = 5" /etc/audisp/audisp-remote.conf ; then
			report_fail SV-90311r1_rule fail
		fi
	fi
}

SV-90315r2_rule ()
{
	if [ ! -f /var/log/audit/audit.log ] ; then
		report_fail SV-90315r2_rule nofile1
	elif [ ! -f /etc/audit/auditd.conf ] ; then
		report_fail SV-90315r2_rule nofile2
	else
		if ! grep --quiet "^log_file = /var/log/audit/audit.log" /etc/audit/auditd.conf ; then
			report_fail SV-90315r2_rule fail1
		elif ! stat -c "%a" /var/log/audit/audit.log | grep --quiet "600" ; then
			report_fail SV-90315r2_rule fail2
		fi
	fi
}

SV-90317r2_rule ()
{
	if [ ! -f /var/log/audit/audit.log ] ; then
		report_fail SV-90317r2_rule nofile1
	elif [ ! -f /etc/audit/auditd.conf ] ; then
		report_fail SV-90317r2_rule nofile2
	else
		if ! grep --quiet "^log_file = /var/log/audit/audit.log" /etc/audit/auditd.conf ; then
			report_fail SV-90317r2_rule fail1
		elif ! stat -c "%a" /var/log/audit | grep --quiet "750" ; then
			report_fail SV-90317r2_rule fail2
		fi
	fi
}

SV-90319r2_rule ()
{
	if [ ! -f /var/log/audit/audit.log ] ; then
		report_fail SV-90317r2_rule nofile
	else	
		if ! ls -la /var/log/audit/audit.log | cut -d " " -f3 | grep --quiet "root" ; then
			report_fail SV-90319r2_rule fail
		fi
	fi
}

SV-90321r2_rule ()
{
	if [ ! -f /etc/audit/auditd.conf ]; then
		report_fail SV-90321r2_rule nofile_/etc/audit/auditd.conf
	else
		log_file=$(grep --word-regexp log_file /etc/audit/auditd.conf | tr -s [[:space:]] | cut -d " " -f 3)
		if [ ! -f $log_file ]; then
			report_fail SV-90321r2_rule "nofile_${log_file}"
		else
			if ! stat -c "%G" $log_file | grep --quiet root; then
				report_fail SV-90321r2_rule fail1
			fi
		fi 
	fi
}

SV-90323r2_rule ()
{
	if [ ! -f /etc/audit/auditd.conf ]; then
		report_fail SV-90323r2_rule nofile_/etc/audit/auditd.conf
	else
		log_dir=$(grep --word-regexp log_file /etc/audit/auditd.conf | cut -d "=" -f 2 | xargs dirname)
		if ! stat -c "%U" $log_dir | grep --quiet root; then
			report_fail SV-90323r2_rule fail1
		fi 
	fi
}

SV-90325r2_rule ()
{
	if [ ! -f /etc/audit/auditd.conf ]; then
		report_fail SV-90325r2_rule nofile_/etc/audit/auditd.conf
	else
		log_dir=$(grep --word-regexp log_file /etc/audit/auditd.conf | cut -d "=" -f 2 | xargs dirname)
		if ! stat -c "%G" $log_dir | grep --quiet root; then
			report_fail SV-90325r2_rule fail1
		fi 
	fi
}

SV-90327r1_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90327r1_rule nofile_/etc/audit/audit.rules
	else
		if [ $(stat -c "%a" /etc/audit/audit.rules) -gt 640 ]; then
			report_fail SV-90327r1_rule fail1
		fi
	fi

	if [ ! -f /etc/audit/auditd.conf ]; then
		report_fail SV-90327r1_rule nofile_/etc/audit/auditd.conf
	else
		if [ $(stat -c "%a" /etc/audit/auditd.conf) -gt 640 ]; then
			report_fail SV-90327r1_rule fail2
		fi
	fi
}

SV-90329r2_rule ()
{
	if [ ! -f /etc/audit/auditd.conf ]; then
		report_fail SV-90329r2_rule nofile_/etc/audit/auditd.conf
	else
		log_file=$(grep --word-regexp log_file /etc/audit/auditd.conf | tr -s [[:space:]] | cut -d " " -f 3)
		if [ ! -f $log_file ]; then
			report_fail SV-90329r2_rule "nofile_${log_file}"
		else
			if ! stat -c "%U" $log_file | grep --quiet root; then
				report_fail SV-90329r2_rule fail1
			fi
		fi
	fi
}

SV-90333r2_rule ()
{
	if [ ! -f /sbin/auditctl ]; then
		report_fail SV-90333r2_rule nofile_/sbin/auditctl
	elif [ $(stat -c "%a" /sbin/auditctl) -gt 755 ] ; then
		report_fail SV-90333r2_rule fail1
	fi
	
	if [ ! -f /sbin/aureport ]; then
		report_fail SV-90333r2_rule nofile_/sbin/aureport
	elif [ $(stat -c "%a" /sbin/aureport) -gt 755 ] ; then
		report_fail SV-90333r2_rule fail2
	fi

	if [ ! -f /sbin/ausearch ]; then
		report_fail SV-90333r2_rule nofile_/sbin/ausearch
	elif [ $(stat -c "%a" /sbin/ausearch) -gt 755 ] ; then
		report_fail SV-90333r2_rule fail3
	fi

	if [ ! -f /sbin/autrace ]; then
		report_fail SV-90333r2_rule nofile_/sbin/autrace
	elif [ $(stat -c "%a" /sbin/autrace) -gt 755 ] ; then
		report_fail SV-90333r2_rule fail4
	fi

	if [ ! -f /sbin/auditd ]; then
		report_fail SV-90333r2_rule nofile_/sbin/auditd
	elif [ $(stat -c "%a" /sbin/auditd) -gt 755 ] ; then
		report_fail SV-90333r2_rule fail5
	fi

	if [ ! -f /sbin/audispd ]; then
		report_fail SV-90333r2_rule nofile_/sbin/audispd
	elif [ $(stat -c "%a" /sbin/audispd) -gt 755 ] ; then
		report_fail SV-90333r2_rule fail6
	fi

	if [ ! -f /sbin/augenrules ]; then
		report_fail SV-90333r2_rule nofile _/sbin/augenrules
	elif [ $(stat -c "%a" /sbin/augenrules) -gt 755 ] ; then
		report_fail SV-90333r2_rule fail7
	fi
}

SV-90335r2_rule ()
{
	if [ ! -f /sbin/auditctl ]; then
		report_fail SV-90335r2_rule nofile_/sbin/auditctl
	elif ! stat -c "%U" /sbin/auditctl | grep --quiet root ; then
		report_fail SV-90335r2_rule fail1
	fi
	
	if [ ! -f /sbin/aureport ]; then
		report_fail SV-90335r2_rule nofile_/sbin/aureport
	elif ! stat -c "%U" /sbin/aureport | grep --quiet root ; then
		report_fail SV-90335r2_rule fail2
	fi

	if [ ! -f /sbin/ausearch ]; then
		report_fail SV-90335r2_rule nofile_/sbin/ausearch
	elif ! stat -c "%U" /sbin/ausearch | grep --quiet root; then
		report_fail SV-90335r2_rule fail3
	fi

	if [ ! -f /sbin/autrace ]; then
		report_fail SV-90335r2_rule nofile_/sbin/autrace
	elif ! stat -c "%U" /sbin/autrace | grep --quiet root; then
		report_fail SV-90335r2_rule fail4
	fi

	if [ ! -f /sbin/auditd ]; then
		report_fail SV-90335r2_rule nofile_/sbin/auditd
	elif ! stat -c "%U" /sbin/auditd | grep --quiet root; then
		report_fail SV-90335r2_rule fail5
	fi

	if [ ! -f /sbin/audispd ]; then
		report_fail SV-90335r2_rule nofile_/sbin/audispd
	elif ! stat -c "%U" /sbin/audispd | grep --quiet root; then
		report_fail SV-90335r2_rule fail6
	fi

	if [ ! -f /sbin/augenrules ]; then
		report_fail SV-90335r2_rule nofile _/sbin/augenrules
	elif ! stat -c "%U" /sbin/augenrules | grep --quiet root; then
		report_fail SV-90335r2_rule fail7
	fi
}

SV-90337r2_rule ()
{
	if [ ! -f /sbin/auditctl ]; then
		report_fail SV-90337r2_rule nofile_/sbin/auditctl
	elif ! stat -c "%G" /sbin/auditctl | grep --quiet root ; then
		report_fail SV-90337r2_rule fail1
	fi
	
	if [ ! -f /sbin/aureport ]; then
		report_fail SV-90337r2_rule nofile_/sbin/aureport
	elif ! stat -c "%G" /sbin/aureport | grep --quiet root ; then
		report_fail SV-90337r2_rule fail2
	fi

	if [ ! -f /sbin/ausearch ]; then
		report_fail SV-90337r2_rule nofile_/sbin/ausearch
	elif ! stat -c "%G" /sbin/ausearch | grep --quiet root; then
		report_fail SV-90337r2_rule fail3
	fi

	if [ ! -f /sbin/autrace ]; then
		report_fail SV-90337r2_rule nofile_/sbin/autrace
	elif ! stat -c "%G" /sbin/autrace | grep --quiet root; then
		report_fail SV-90337r2_rule fail4
	fi

	if [ ! -f /sbin/auditd ]; then
		report_fail SV-90337r2_rule nofile_/sbin/auditd
	elif ! stat -c "%G" /sbin/auditd | grep --quiet root; then
		report_fail SV-90337r2_rule fail5
	fi

	if [ ! -f /sbin/audispd ]; then
		report_fail SV-90337r2_rule nofile_/sbin/audispd
	elif ! stat -c "%G" /sbin/audispd | grep --quiet root; then
		report_fail SV-90337r2_rule fail6
	fi

	if [ ! -f /sbin/augenrules ]; then
		report_fail SV-90337r2_rule nofile _/sbin/augenrules
	elif ! stat -c "%G" /sbin/augenrules | grep --quiet root; then
		report_fail SV-90337r2_rule fail7
	fi
}

SV-90339r2_rule ()
{
	if ! apt list audispd-plugins 2>/dev/null| grep --quiet --word-regexp installed; then
		report_fail SV-90339r2_rule notinstalled_audispd-plugins
	else
		if [ ! -f /etc/audisp/plugins.d/au-remote.conf ]; then
			report_fail SV-90339r2_rule nofile
		else
			if ! grep --quiet "active = yes" /etc/audisp/plugins.d/au-remote.conf; then
				report_fail SV-90339r2_rule fail1
			fi
		fi
	fi
}
SV-90341r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90341r3_rule nofile
	else
		if ! grep --quiet "^\-w /etc/passwd \-p wa \-k identity" /etc/audit/audit.rules; then
			report_fail SV-90341r3_rule fail1
		fi
	fi
}
		
SV-90343r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90343r3_rule nofile
	else
		if ! grep --quiet "^\-w /etc/group \-p wa \-k identity" /etc/audit/audit.rules; then
			report_fail SV-90343r3_rule fail1
		fi
	fi
}
		
SV-90345r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90345r3_rule nofile
	else
		if ! grep --quiet "^\-w /etc/gshadow \-p wa \-k identity" /etc/audit/audit.rules; then
			report_fail SV-90345r3_rule fail1
		fi
	fi
}
		
SV-90347r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90347r3_rule nofile
	else
		if ! grep --quiet "^\-w /etc/shadow \-p wa \-k identity" /etc/audit/audit.rules; then
			report_fail SV-90347r3_rule fail1
		fi
	fi
}
		
SV-90367r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90367r3_rule nofile
	else
		if ! grep --quiet "^\-w /etc/security/opasswd \-p wa \-k audit_rules_usergroup_modification" /etc/audit/audit.rules; then
			report_fail SV-90367r3_rule fail1
		fi
	fi
}
		
SV-90369r2_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90369r2_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S execve \-C uid!=euid \-F key=execpriv" /etc/audit/audit.rules; then
			report_fail SV-90369r2_rule fail1
		fi
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S execve \-C gid!=egid \-F key=execpriv" /etc/audit/audit.rules; then
			report_fail SV-90369r2_rule fail2
		fi
	fi
}
		
SV-90371r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90371r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/bin/su \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k privileged-priv_change" /etc/audit/audit.rules; then
			report_fail SV-90371r3_rule fail1
		fi
	fi
}
		
SV-90373r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90373r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/usr/bin/chfn \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k privileged-gpasswd" /etc/audit/audit.rules; then
			report_fail SV-90373r3_rule fail1
		fi
	fi
}
		
SV-90375r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90375r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/bin/mount \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k privileged-mount" /etc/audit/audit.rules; then
			report_fail SV-90375r3_rule fail1
		fi
	fi
}
		
SV-90377r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90377r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/bin/umount \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k privileged-mount" /etc/audit/audit.rules; then
			report_fail SV-90377r3_rule fail1
		fi
	fi
}
		
SV-90379r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90379r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/usr/bin/ssh-agent \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k privileged-ssh" /etc/audit/audit.rules; then
			report_fail SV-90379r3_rule fail1
		fi
	fi
}
		
SV-90387r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90387r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/usr/lib/openssh/ssh-keysign \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k privileged-ssh" /etc/audit/audit.rules; then
			report_fail SV-90387r3_rule fail1
		fi
	fi
}
		
SV-90389r2_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90389r2_rule nofile
	else
		if ! grep --quiet "^\-w /sbin/insmod \-p x \-k modules" /etc/audit/audit.rules; then
			report_fail SV-90389r2_rule fail1
		fi
	fi
}
		
SV-90391r2_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90391r2_rule nofile
	else
		if ! grep --quiet "^\-w /sbin/rmmod \-p x \-k modules" /etc/audit/audit.rules; then
			report_fail SV-90391r2_rule fail1
		fi
	fi
}
		
SV-90393r2_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90393r2_rule nofile
	else
		if ! grep --quiet "^\-w /sbin/modprobe \-p x \-k modules" /etc/audit/audit.rules; then
			report_fail SV-90393r2_rule fail1
		fi
	fi
}
		
SV-90395r2_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90395r2_rule nofile
	else
		if ! grep --quiet "^\-w /bin/kmod \-p x \-k modules" /etc/audit/audit.rules; then
			report_fail SV-90395r2_rule fail1
		fi
	fi
}
		
SV-90397r2_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90397r2_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S setxattr \-F auid>=1000 \-F auid!=4294967295 \-k perm_mod" /etc/audit/audit.rules; then
			report_fail SV-90397r2_rule fail1
		fi
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S setxattr \-F auid=0 \-k perm_mod" /etc/audit/audit.rules; then
			report_fail SV-90397r2_rule fail2
		fi
	fi
}
		
SV-90399r2_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90399r2_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S lsetxattr \-F auid>=1000 \-F auid!=4294967295 \-k perm_mod" /etc/audit/audit.rules; then
			report_fail SV-90399r2_rule fail1
		fi
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S lsetxattr \-F auid=0 \-k perm_mod" /etc/audit/audit.rules; then
			report_fail SV-90399r2_rule fail2
		fi
	fi
}
		
SV-90401r2_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90401r2_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S fsetxattr \-F auid>=1000 \-F auid!=4294967295 \-k perm_mod" /etc/audit/audit.rules; then
			report_fail SV-90401r2_rule fail1
		fi
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S fsetxattr \-F auid=0 \-k perm_mod" /etc/audit/audit.rules; then
			report_fail SV-90401r2_rule fail2
		fi
	fi
}
		
SV-90403r2_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90403r2_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S removexattr \-F auid>=1000 \-F auid!=4294967295 \-k perm_mod" /etc/audit/audit.rules; then
			report_fail SV-90403r2_rule fail1
		fi
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S removexattr \-F auid=0 \-k perm_mod" /etc/audit/audit.rules; then
			report_fail SV-90403r2_rule fail2
		fi
	fi
}
		
SV-90405r2_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90405r2_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S lremovexattr \-F auid>=1000 \-F auid!=4294967295 \-k perm_mod" /etc/audit/audit.rules; then
			report_fail SV-90405r2_rule fail1
		fi
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S lremovexattr \-F auid=0 \-k perm_mod" /etc/audit/audit.rules; then
			report_fail SV-90405r2_rule fail2
		fi
	fi
}
		
SV-90407r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90407r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S fremovexattr \-F auid>=1000 \-F auid!=4294967295 \-k perm_mod" /etc/audit/audit.rules; then
			report_fail SV-90407r3_rule fail1
		fi
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S fremovexattr \-F auid=0 \-k perm_mod" /etc/audit/audit.rules; then
			report_fail SV-90407r3_rule fail2
		fi
	fi
}
		
SV-90409r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90409r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S chown \-F auid>=1000 \-F auid!=4294967295 \-k perm_chng" /etc/audit/audit.rules; then
			report_fail SV-90409r3_rule fail1
		fi
	fi
}
		
SV-90411r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90411r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S fchown \-F auid>=1000 \-F auid!=4294967295 \-k perm_chng" /etc/audit/audit.rules; then
			report_fail SV-90411r3_rule fail1
		fi
	fi
}
		
SV-90413r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90413r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S fchownat \-F auid>=1000 \-F auid!=4294967295 \-k perm_chng" /etc/audit/audit.rules; then
			report_fail SV-90413r3_rule fail1
		fi
	fi
}
		
SV-90415r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90415r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S lchown \-F auid>=1000 \-F auid!=4294967295 \-k perm_chng" /etc/audit/audit.rules; then
			report_fail SV-90415r3_rule fail1
		fi
	fi
}
		
SV-90417r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90417r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S chmod \-F auid>=1000 \-F auid!=4294967295 \-k perm_chng" /etc/audit/audit.rules; then
			report_fail SV-90417r3_rule fail1
		fi
	fi
}
		
SV-90419r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90419r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S fchmod \-F auid>=1000 \-F auid!=4294967295 \-k perm_chng" /etc/audit/audit.rules; then
			report_fail SV-90419r3_rule fail1
		fi
	fi
}
		
SV-90421r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90421r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S fchmodat \-F auid>=1000 \-F auid!=4294967295 \-k perm_chng" /etc/audit/audit.rules; then
			report_fail SV-90421r3_rule fail1
		fi
	fi
}
		
SV-90423r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90423r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S open \-F exit=\-EPERM \-F auid>=1000 \-F auid!=4294967295 \-k perm_access" /etc/audit/audit.rules; then
			report_fail SV-90423r3_rule fail1
		fi
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S open \-F exit=\-EACCES \-F auid>=1000 \-F auid!=4294967295 \-k perm_access" /etc/audit/audit.rules; then
			report_fail SV-90423r3_rule fail2
		fi
	fi
}
		
SV-90425r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90425r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S truncate \-F exit=\-EPERM \-F auid>=1000 \-F auid!=4294967295 \-k perm_access" /etc/audit/audit.rules; then
			report_fail SV-90425r3_rule fail1
		fi
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S truncate \-F exit=\-EACCES \-F auid>=1000 \-F auid!=4294967295 \-k perm_access" /etc/audit/audit.rules; then
			report_fail SV-90425r3_rule fail2
		fi
	fi
}
		
SV-90427r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90427r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S ftruncate \-F exit=\-EPERM \-F auid>=1000 \-F auid!=4294967295 \-k perm_access" /etc/audit/audit.rules; then
			report_fail SV-90427r3_rule fail1
		fi
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S ftruncate \-F exit=\-EACCES \-F auid>=1000 \-F auid!=4294967295 \-k perm_access" /etc/audit/audit.rules; then
			report_fail SV-90427r3_rule fail2
		fi
	fi
}
		
SV-90429r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90429r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S creat \-F exit=\-EPERM \-F auid>=1000 \-F auid!=4294967295 \-k perm_access" /etc/audit/audit.rules; then
			report_fail SV-90429r3_rule fail1
		fi
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S creat \-F exit=\-EACCES \-F auid>=1000 \-F auid!=4294967295 \-k perm_access" /etc/audit/audit.rules; then
			report_fail SV-90429r3_rule fail2
		fi
	fi
}
		
SV-90431r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90431r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S openat \-F exit=\-EPERM \-F auid>=1000 \-F auid!=4294967295 \-k perm_access" /etc/audit/audit.rules; then
			report_fail SV-90431r3_rule fail1
		fi
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S openat \-F exit=\-EACCES \-F auid>=1000 \-F auid!=4294967295 \-k perm_access" /etc/audit/audit.rules; then
			report_fail SV-90431r3_rule fail2
		fi
	fi
}
		
SV-90433r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90433r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S open_by_handle_at \-F exit=\-EPERM \-F auid>=1000 \-F auid!=4294967295 \-k perm_access" /etc/audit/audit.rules; then
			report_fail SV-90433r3_rule fail1
		fi
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S open_by_handle_at \-F exit=\-EACCES \-F auid>=1000 \-F auid!=4294967295 \-k perm_access" /etc/audit/audit.rules; then
			report_fail SV-90433r3_rule fail2
		fi
	fi
}
		
SV-90435r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90435r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/usr/bin/sudo \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k priv_cmd" /etc/audit/audit.rules; then
			report_fail SV-90435r3_rule fail1
		fi
	fi
}
		
SV-90437r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90437r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/usr/bin/sudoedit \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k priv_cmd" /etc/audit/audit.rules; then
			report_fail SV-90437r3_rule fail1
		fi
	fi
}
		
SV-90439r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90439r3_rule nofile
	else
		if ! grep --quiet "\-a always,exit \-F path=/usr/bin/chsh \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k priv_cmd" /etc/audit/audit.rules; then
			report_fail SV-90439r3_rule fail1
		fi
	fi
}
		
SV-90441r4_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90441r4_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/usr/bin/newgrp \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k priv_cmd" /etc/audit/audit.rules; then
			report_fail SV-90441r4_rule fail1
		fi
	fi
}
		
SV-90445r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90445r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/sbin/apparmor_parser \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k privileged-chng" /etc/audit/audit.rules; then
			report_fail SV-90445r3_rule fail1
		fi
	fi
}
		
SV-90447r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90447r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/usr/bin/setfacl \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k privileged-chng" /etc/audit/audit.rules; then
			report_fail SV-90447r3_rule fail1
		fi
	fi
}
		
SV-90449r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90449r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/usr/bin/chacl \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k privileged-chng" /etc/audit/audit.rules; then
			report_fail SV-90449r3_rule fail1
		fi
	fi
}
		
SV-90451r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90451r3_rule nofile
	else
		if ! grep --quiet "^\-w /var/log/tallylog \-p wa \-k logins" /etc/audit/audit.rules; then
			report_fail SV-90451r3_rule fail1
		fi
	fi
}
		
SV-90453r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90453r3_rule nofile
	else
		if ! grep --quiet "^\-w /var/log/faillog \-p wa \-k logins" /etc/audit/audit.rules; then
			report_fail SV-90453r3_rule fail1
		fi
	fi
}
		
SV-90455r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90455r3_rule nofile
	else
		if ! grep --quiet "^\-w /var/log/lastlog \-p wa \-k logins" /etc/audit/audit.rules; then
			report_fail SV-90455r3_rule fail1
		fi
	fi
}
		
SV-90457r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90457r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/usr/bin/passwd \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k privileged-passwd" /etc/audit/audit.rules; then
			report_fail SV-90457r3_rule fail1
		fi
	fi
}
		
SV-90459r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90459r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/sbin/unix_update \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k privileged-unix-update" /etc/audit/audit.rules; then
			report_fail SV-90459r3_rule fail1
		fi
	fi
}
		
SV-90461r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90461r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/usr/bin/gpasswd \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k privileged-gpasswd" /etc/audit/audit.rules; then
			report_fail SV-90461r3_rule fail1
		fi
	fi
}
		
SV-90463r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90463r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/usr/bin/chage \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k privileged-chage" /etc/audit/audit.rules; then
			report_fail SV-90463r3_rule fail1
		fi
	fi
}
		
SV-90465r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90465r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/usr/sbin/usermod \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k privileged-usermod" /etc/audit/audit.rules; then
			report_fail SV-90465r3_rule fail1
		fi
	fi
}
		
SV-90467r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90467r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/usr/bin/crontab \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k privileged-crontab" /etc/audit/audit.rules; then
			report_fail SV-90467r3_rule fail1
		fi
	fi
}
		
SV-90469r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90469r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F path=/usr/sbin/pam_timestamp_check \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k privileged-pam_timestamp_check" /etc/audit/audit.rules; then
			report_fail SV-90469r3_rule fail1
		fi
	fi
}
		
SV-90471r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90471r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S init_module \-F auid>=1000 \-F auid!=4294967295 \-k module_chng" /etc/audit/audit.rules; then
			report_fail SV-90471r3_rule fail1
		fi
	fi
}
		
SV-90473r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90473r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S finit_module \-F auid>=1000 \-F auid!=4294967295 \-k module_chng" /etc/audit/audit.rules; then
			report_fail SV-90473r3_rule fail1
		fi
	fi
}

SV-90475r3_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-90475r3_rule nofile
	else
		if ! grep --quiet "^\-a always,exit \-F arch=b64 \-S delete_module \-F auid>=1000 \-F auid!=4294967295 \-k module_chng" /etc/audit/audit.rules; then
			report_fail SV-90475r3_rule fail1
		fi
	fi
}

SV-90477r2_rule ()
{
	if apt list telnetd 2>/dev/null | grep --quiet --word-regexp "installed"; then
		report_fail SV-90477r2_rule fail1
	fi
}

SV-90479r2_rule ()
{
	if apt list nis 2>/dev/null | grep --quiet --word-regexp "installed"; then
		report_fail SV-90479r2_rule fail1
	fi
}

SV-90481r2_rule ()
{
	if apt list rsh-server 2>/dev/null | grep --quiet --word-regexp "installed"; then
		report_fail SV-90481r2_rule fail1
	fi
}

SV-90483r2_rule ()
{
	if ! apt list ufw 2>/dev/null| grep --quiet --word-regexp "installed"; then
		report_fail SV-90483r2_rule fail1
	fi
}

SV-90485r2_rule ()
{
	if ! apt list ufw 2>/dev/null| grep --quiet --word-regexp "installed"; then
		report_fail SV-90485r2_rule notinstalled
	else
		if ! systemctl is-enabled ufw |grep --quiet "enabled"; then
			report_fail SV-90485r2_rule fail1
		fi
	fi
}

SV-90487r2_rule ()
{
	report_fail SV-90487r2_rule check_stig
}

SV-90489r2_rule ()
{
	report_fail SV-90489r2_rule check_stig
}

SV-90491r4_rule ()
{
	if find / -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null|grep --quiet ".*"; then
		report_fail SV-90491r4_rule fail1
	fi
}

SV-90493r2_rule ()
{
	if [ ! -f /etc/ntp.conf ]; then
		report_fail SV-90493r2_rule nofile
	else
		if ! grep --quiet "^maxpoll 17" /etc/ntp.conf; then
			report_fail SV-90493r2_rule fail1
		fi
	fi
}

SV-90497r2_rule ()
{
	if ! timedatectl status | grep -i "time zone: America/New_York (EST, -0500)" ; then
		report_fail SV-90497r2_rule fail1
	fi
}

SV-90499r2_rule ()
{
	if [ ! -f /proc/cpuinfo ]; then
		report_fail SV-90499r2_rule nofile
	else
		if ! dmesg | grep --quiet "NX (Execute Disable) protection: active"; then
			report_fail SV-90499r2_rule fail1
		fi
		if ! grep flags /proc/cpuinfo | grep -w --quiet nx; then
			report_fail SV-90499r2_rule fail2
		fi
	fi
}

SV-90501r2_rule ()
{
	if ! sysctl -a 2> /dev/null|grep --quiet "kernel.randomize_va_space = 2"; then
		report_fail SV-90501r2_rule fail1
	fi
}

SV-90503r2_rule ()
{
	if [ ! -f /etc/ssh/sshd_config ]; then
		report_fail SV-90503r2_rule nofile
	else
		if ! grep --quiet "^Protocol 2" /etc/ssh/sshd_config; then
			report_fail SV-90503r2_rule fail1
		fi
		if ! sshd -T | grep --quiet --ignore-case "^Protocol 2"; then
			report_fail SV-90503r2_rule fail2
		fi
	fi
}

SV-90505r2_rule ()
{
	if [ ! -f /etc/ssh/sshd_config ]; then
		report_fail SV-90505r2_rule nofile
	else
		if ! grep --quiet "^Banner /etc/issue" /etc/ssh/sshd_config; then
			report_fail SV-90505r2_rule fail1
		fi
		if ! sshd -T | grep --quiet --ignore-case "Banner /etc/issue"; then
			report_fail SV-90505r2_rule fail2
		fi
	fi
}

SV-90507r2_rule ()
{
	if [ ! -f /etc/ssh/sshd_config ]; then
		report_fail SV-90507r2_rule nofile
	else
		if ! grep --quiet "^PermitRootLogin no" /etc/ssh/sshd_config; then
			report_fail SV-90507r2_rule fail1
		fi
		# sshd is not running with PermitRootLogin no
		if ! sshd -T | grep --quiet --ignore-case "PermitRootLogin no"; then
			report_fail SV-90507r2_rule fail2
		fi
	fi
}

SV-90509r2_rule ()
{
	report_fail SV-90509r2_rule conflict_with_checklist_website
}

SV-90511r2_rule ()
{
	if [ ! -f /etc/ssh/sshd_config ]; then
		report_fail SV-90511r2_rule nofile
	else
		if ! grep --quiet "^MACs hmac-sha2-256,hmac-sha2-512" /etc/ssh/sshd_config; then
			report_fail SV-90511r2_rule fail1
		fi
		# sshd is not running with MACs hmac-sha2-256 hmac-sha2-512
		if ! sshd -T | grep --quiet --ignore-case "MACs hmac-sha2-256,hmac-sha2-512"; then
			report_fail SV-90511r2_rule fail2
		fi
	fi
	
}

SV-90513r2_rule ()
{
	if [ ! -f /etc/ssh/sshd_config ]; then
		report_fail SV-90513r2_rule nofile
	else
		if ! grep --quiet "^PermitEmptyPasswords no" /etc/ssh/sshd_config; then
			report_fail SV-90513r2_rule fail1
		fi
		if ! grep --quiet "^PermitUserEnvironment no" /etc/ssh/sshd_config; then
			report_fail SV-90513r2_rule fail2
		fi
		if ! sshd -T | grep --quiet --ignore-case "PermitEmptyPasswords no"; then
			report_fail SV-90513r2_rule fail3
		fi
		if ! sshd -T | grep --quiet --ignore-case "PermitUserEnvironment no"; then
			report_fail SV-90513r2_rule fail4
		fi
	fi
}

SV-90515r2_rule ()
{
	if [ ! -f /etc/ssh/sshd_config ]; then
		report_fail SV-90515r2_rule nofile
	else
		if ! grep --quiet "^PrintLastLog yes" /etc/ssh/sshd_config; then
			report_fail SV-90515r2_rule fail1
		fi
		if ! sshd -T | grep --quiet --ignore-case "PrintLastLog yes"; then
			report_fail SV-90515r2_rule fail2
		fi
	fi
}

SV-90517r2_rule ()
{
	if [ ! -f /etc/ssh/sshd_config ]; then
		report_fail SV-90517r2_rule nofile
	else
		if ! grep --quiet "^ClientAliveInterval 600" /etc/ssh/sshd_config; then
			report_fail SV-90517r2_rule fail1
		fi
		if ! grep --quiet "^ClientAliveCountMax 1" /etc/ssh/sshd_config; then
			report_fail SV-90517r2_rule fail2
		fi
		if ! sshd -T | grep --quiet --ignore-case "ClientAliveInterval 600"; then
			report_fail SV-90517t2_rule fail3
		fi
		if ! sshd -T | grep --quiet --ignore-case "ClientAliveCountMax 1"; then
			report_fail SV-90517t2_rule fail4
		fi
	fi
}

SV-90521r2_rule ()
{
	if [ ! -f /etc/ssh/sshd_config ]; then
		report_fail SV-90521r2_rule nofile
	else
		if ! grep --quiet "^IgnoreUserKnownHosts yes" /etc/ssh/sshd_config; then
			report_fail SV-90521r2_rule fail1
		fi
		if ! sshd -T | grep --quiet --ignore-case "IgnoreUserKnownHosts yes"; then
			report_fail SV-90521r2_rule fail3
		fi 
	fi
}

SV-90523r2_rule ()
{
	if ! find /etc/ssh -name "*.pub" | grep --quiet ""; then
		report_fail SV-90523r2_rule nofile_/etc/ssh/any_pub_file
	else
		for filename in /etc/ssh/*.pub; do
			if [ $(stat -c "%a" $filename) -gt 644 ]; then
				report_fail SV-90523r2_rule fail_$filename
			fi
			# fix
			# sudo chmod 644 /etc/ssh/*.pub
		done
	fi
}

SV-90525r2_rule ()
{
	if ! find /etc/ssh -name "ssh_host*key" | grep --quiet ""; then
		report_fail SV-90525r2_rule nofile_/etc/ssh/ssh_host_star_key
	else
		for filename in /etc/ssh/ssh_host*key; do
			if [ $(stat -c "%a" $filename) -gt 600 ]; then
				report_fail SV-90525r2_rule fail
			fi
			# fix
			# sudo chmod 600 /etc/ssh/ssh_host*key
		done
	fi
#	ls /etc/ssh/ssh*key|xargs -I arg stat -c "%a" arg
}

SV-90527r2_rule ()
{
	if [ ! -f /etc/ssh/sshd_config ]; then
		report_fail SV-90527r2_rule nofile
	else
		if ! grep --quiet "StrictModes yes" /etc/ssh/sshd_config; then
			report_fail SV-90527r2_rule fail
		fi
	fi
}

SV-90529r2_rule ()
{
	if [ ! -f /etc/ssh/sshd_config ]; then
		report_fail SV-90529r2_rule nofile
	else
		if ! grep --quiet "UsePrivilegeSeparation yes" /etc/ssh/sshd_config; then
			report_fail SV-90529r2_rule fail
		fi
	fi
}

SV-90531r2_rule ()
{
	if [ ! -f /etc/ssh/sshd_config ]; then
		report_fail SV-90531r2_rule nofile
	else
		if ! grep --quiet "Compression delayed" /etc/ssh/sshd_config; then
			report_fail SV-90531r2_rule fail
		fi
	fi
}

SV-90533r2_rule ()
{
	if [ ! -f /etc/ssh/sshd_config ]; then
		report_fail SV-90533r2_rule nofile
	else
		if ! grep --quiet "X11Forwarding yes" /etc/ssh/sshd_config; then
			report_fail SV-90533r2_rule fail
		fi
	fi
}

SV-90535r1_rule ()
{
	report_fail SV-90535r1_rule check_stig
}

SV-90539r2_rule ()
{
	if [ ! -f /etc/audisp/audisp-remote.conf ]; then
		report_fail SV-90539r2_rule nofile
	else
		if ! grep "^network_failure = stop" /etc/audisp/audisp-remote.conf ; then
			report_fail  SV-90539r2_rule fail1
		fi
	fi
}

SV-90543r2_rule ()
{
	if [ ! -f /etc/rsyslog.d/50-default.conf ]; then
		report_fail SV-90543r2_rule nofile
	else
		if ! grep -v "#" /etc/rsyslog.d/50-default.conf |grep --quiet --word-regexp auth; then
			report_fail SV-90543r2_rule fail1
		fi
		if ! grep -v "#" /etc/rsyslog.d/50-default.conf |grep --quiet --word-regexp authpriv; then
			report_fail SV-90543r2_rule fail2
		fi
		if ! grep -v "#" /etc/rsyslog.d/50-default.conf |grep --quiet --word-regexp daemon; then
			report_fail SV-90543r2_rule fail3
		fi
	fi
}

SV-90545r2_rule ()
{
	if [ ! -f /etc/rsyslog.d/50-default.conf ]; then
		report_fail SV-90545r2_rule nofile
	else
		if ! grep --quiet "^cron\.\*				/var/log/cron.log" /etc/rsyslog.d/50-default.conf; then
			if ! grep --quiet "^\*\.\*" /etc/rsyslog.d/50-default.conf; then
				report_fail SV-90545r2_rule fail1
			fi
		fi

		if grep --quiet "^\*\.\*[[:space:]]*~" /etc/rsyslog.d/50-default.conf; then
			report_fail SV-90545r2_rule check_the_stig
		fi
	fi
}

SV-90547r1_rule ()
{
	if ifconfig -a | grep --quiet wlan; then
		report_fail SV-90547r1_rule fail
	fi
	## fix
	## ifconfig -q |grep wlan
	## sudo ifdown [wlan return from last command]
}

SV-90549r2_rule ()
{
	if [ ! -f /etc/sysctl.conf ]; then
		report_fail SV-90549r2_rule nofile
	else
		if ! sysctl -a 2>/dev/null| grep --quiet "^net.ipv4.tcp_syncookies=1" ; then
			report_fail SV-90549r2_rule fail1
		fi
		if ! grep --quiet "^net.ipv4.tcp_syncookies=1" /etc/sysctl.conf; then
			report_fail SV-90549r2_rule fail2
		fi
	fi
}

SV-90551r2_rule ()
{
	if [ ! -f /etc/nsswitch.conf ]; then
		report_fail SV-90551r2_rule nofile1
	else
		## ubuntu is using local or DNS
		if grep "^hosts" /etc/nsswitch.conf | grep --quiet --word-regexp dns ; then
			if [ ! -f /etc/resolv.conf ]; then
				report_file SV-90551r2_rule nofile2
			else
				## check if there are at least tow nameserver
				num_of_nameserver=$(grep -c "^nameserver" /etc/resolv.conf)
				if [ $num_of_nameserver -lt 2 ];then
					report_fail SV-90551r2_rule fail1
				fi
			fi
		else
		## ubuntu is not using local or DNS
			if [ ! -f /etc/resolv.conf ]; then
				report_file SV-90551r2_rule nofile2
			else
				if grep --quiet --invert-match "^#" /etc/resolv.conf; then
					report_fail SV-90551r2_rule fail2
				fi
			fi
		fi
	fi
}

SV-90553r2_rule ()
{
	if [ ! -f /etc/sysctl.conf ]; then
		report_fail SV-90553r2_rule nofile
	else
		if ! sysctl -a 2>/dev/null| grep --quiet "^net.ipv4.conf.all.accept_source_route = 0" ; then
			report_fail SV-90553r2_rule fail1
		fi
		if ! grep --quiet "^net.ipv4.conf.all.accept_source_route = 0" /etc/sysctl.conf; then
			report_fail SV-90553r2_rule fail2
		fi
	fi
}

SV-90555r2_rule ()
{
	if [ ! -f /etc/sysctl.conf ]; then
		report_fail SV-90555r2_rule nofile
	else
		if ! sysctl -a 2>/dev/null| grep --quiet "net.ipv4.conf.default.accept_source_route = 0" ; then
			report_fail SV-90555r2_rule fail1
		fi
		if ! grep --quiet "^net.ipv4.conf.default.accept_source_route = 0" /etc/sysctl.conf; then
			report_fail SV-90555r2_rule fail2
		fi
	fi
}

SV-90557r2_rule ()
{
	if [ ! -f /etc/sysctl.conf ]; then
		report_fail SV-90557r2_rule nofile
	else
		if ! sysctl -a 2>/dev/null| grep --quiet "^net.ipv4.icmp_echo_ignore_broadcasts = 1" ; then
			report_fail SV-90557r2_rule fail1
		fi
		if ! grep --quiet "^net.ipv4.icmp_echo_ignore_broadcasts = 1" /etc/sysctl.conf; then
			report_fail SV-90557r2_rule fail2
		fi
	fi
}

SV-90559r2_rule ()
{
	if [ ! -f /etc/sysctl.conf ]; then
		report_fail SV-90559r2_rule nofile
	else
		if ! sysctl -a 2>/dev/null| grep --quiet "net.ipv4.conf.default.accept_redirects = 0" ; then
			report_fail SV-90559r2_rule fail1
		fi
		if ! grep --quiet "^net.ipv4.conf.default.accept_redirects = 0" /etc/sysctl.conf; then
			report_fail SV-90559r2_rule fail2
		fi
	fi
}

SV-90561r2_rule ()
{
	if [ ! -f /etc/sysctl.conf ]; then
		report_fail SV-90561r2_rule nofile
	else
		if ! sysctl -a 2>/dev/null| grep --quiet "net.ipv4.conf.all.accept_redirects = 0" ; then
			report_fail SV-90561r2_rule fail1
		fi
		if ! grep --quiet "^net.ipv4.conf.all.accept_redirects = 0" /etc/sysctl.conf; then
			report_fail SV-90561r2_rule fail2
		fi
	fi
}

SV-90563r2_rule ()
{
	if [ ! -f /etc/sysctl.conf ]; then
		report_fail SV-90563r2_rule nofile
	else
		if ! sysctl -a 2>/dev/null| grep --quiet "net.ipv4.conf.default.send_redirects = 0" ; then
			report_fail SV-90563r2_rule fail1
		fi
		if ! grep --quiet "^net.ipv4.conf.default.send_redirects = 0" /etc/sysctl.conf; then
			report_fail SV-90563r2_rule fail2
		fi
	fi
}

SV-90565r2_rule ()
{
	if [ ! -f /etc/sysctl.conf ]; then
		report_fail SV-90565r2_rule nofile
	else
		if ! sysctl -a 2>/dev/null| grep --quiet "net.ipv4.conf.all.send_redirects = 0" ; then
			report_fail SV-90565r2_rule fail1
		fi
		if ! grep --quiet "^net.ipv4.conf.all.send_redirects = 0" /etc/sysctl.conf; then
			report_fail SV-90565r2_rule fail2
		fi
	fi
}

SV-90567r2_rule ()
{
	if [ ! -f /etc/sysctl.conf ]; then
		report_fail SV-90567r2_rule nofile
	else
		if ! sysctl -a 2>/dev/null| grep --quiet "net.ipv4.ip_forward = 0" ; then
			report_fail SV-90567r2_rule fail1
		fi
		if ! grep --quiet "^net.ipv4.ip_forward=0" /etc/sysctl.conf; then
			report_fail SV-90567r2_rule fail2
		fi
	fi
	## fix 
	## add net.ipv4.ip_forward to /etc/sysctl.conf
	## run sysctl -p
}

SV-90569r2_rule ()
{
	if ip link | grep --quiet --ignore-case promisc ; then
		report_fail SV-90569r2_rule fail
	fi
}

SV-90583r1_rule ()
{
	if ! apt list libpam-pkcs11 2>/dev/null | grep --quiet --word-regexp "installed"; then
		report_fail SV-90583r1_rule notinstalled
	fi
}

SV-90585r1_rule ()
{
	if ! dpkg -l | grep --quiet opensc-pkcs11; then
		report_fail SV-90585r1_rule notinstalled
	fi
}

SV-90587r1_rule ()
{
	if [ ! -f /etc/pam_pkcs11/pam_pkcs11.conf ]; then
		report_fail SV-90587r1_rule nofile
	else
		if ! grep --quiet "^cert_policy = ca,signature,ocsp_on;" /etc/pam_pkcs11/pam_pkcs11.conf; then
			report_fail SV-90589r1_rule fail1
		elif grep --quiet "^cert_policy" /etc/pam_pkcs11/pam_pkcs11.conf | grep --quiet "none" /etc/pam_pkcs11/pam_pkcs11.conf; then
			report_fail SV-90589r1_rule fail2
		fi
	fi
}

SV-90589r1_rule ()
{
	if [ ! -f /etc/pam_pkcs11/pam_pkcs11.conf ]; then
		report_fail SV-90589r1_rule nofile
	else
		if ! grep --quiet "^cert_policy = ca,signature,ocsp_on;" /etc/pam_pkcs11/pam_pkcs11.conf; then
			report_fail SV-90589r1_rule fail1
		elif grep --quiet "^cert_policy" /etc/pam_pkcs11/pam_pkcs11.conf | grep --quiet "none" /etc/pam_pkcs11/pam_pkcs11.conf; then
			report_fail SV-90589r1_rule fail2
		fi
	fi
}

SV-90591r1_rule ()
{
	if [ ! -f /etc/pam.d/common-auth ]; then
		report_fail SV-90591r1_rule nofile
	else
		if ! grep --quiet "^auth \[success=2 default=ignore\] pam_pkcs11.so" /etc/pam.d/common-auth; then
			report_fail SV-90591r1_rule fail
		fi
	fi
}

SV-92701r1_rule ()
{
	if ! systemctl status clamav-daemon | grep --quiet "Active: active" ; then
		report_fail SV-92701r1_rule fail
	fi
}

SV-92703r1_rule ()
{
	if [ ! -f /etc/clamav/freshclam.conf ]; then
		report_fail SV-92703r1_rule nofile
	else
		DatabaseDirectory=$(grep DatabaseDirector /etc/clamav/freshclam.conf | tr -s [[:space:]] | cut -d " " -f 2)
		if ! find $DatabaseDirectory -name "*.cvd" -mtime -7 | grep --quiet "."; then
			report_fail SV-92703r1_rule fail
		fi
	fi
}

SV-95669r1_rule ()
{
	if [ ! -e /etc/dconf/db/local.d ]; then
		report_fail SV-95669r1_rule nofile
	else
		if ! grep --quiet logout=\'\' /etc/dconf/db/local.d/* ;then
			report_fail SV-95669r1_rule fail
		fi
	fi
}

SV-95671r1_rule ()
{
	if ! systemctl is-active --quiet auditd; then
		report_fail SV-95671r1_rule fail_auditd_not_running
	fi
}
	
SV-95673r1_rule ()
{
	if [ ! -f /etc/audit/auditd.conf ]; then
		report_fail SV-95673r1_rule nofile_/etc/audit/auditd.conf
	else
		if ! grep --quiet "^space_left = 250" /etc/audit/auditd.conf; then
			report_fail SV-95673r1_rule fail1
		fi
	fi
}

SV-95675r1_rule ()
{
	if [ ! -f /etc/audit/auditd.conf ]; then
		report_fail SV-95675r1_rule nofile_/etc/audit/auditd.conf
	else
		if ! grep --quiet "^log_file = /var/log/audit/audit.log" /etc/audit/auditd.conf; then
			report_fail SV-95675r1_rule
		fi

		log_file=$(grep --word-regexp log_file /etc/audit/auditd.conf | tr -s [[:space:]] | cut -d " " -f 3)
		if [ ! -f $log_file ]; then
			report_fail SV-95675r1_rule "nofile_${log_file}"
		else
			if [ $(stat -c "%a" $log_file) -gt 640 ] ; then
				report_fail SV-95675r1_rule fail1
			fi
		fi
	fi
}

SV-95677r1_rule ()
{
	if [ ! -f /etc/audisp/audisp-remote.conf ]; then
		report_fail SV-95677r1_rule nofile_/etc/audisp/audisp-remote.conf
	else
		if ! grep --quiet "^remote_server = 10.0.1.2" /etc/audisp/audisp-remote.conf; then
			report_fail SV-95677r1_rule fail1
		fi
	fi
}

SV-95681r1_rule ()
{
	if [ ! -f /etc/audit/audit.rules ]; then
		report_fail SV-95681r1_rule nofile_/etc/audit/audit.rules
	else
		if ! grep --quiet "^\-a always,exit \-F path=/usr/bin/chron \-F perm=x \-F auid>=1000 \-F auid!=4294967295 \-k perm_chng" /etc/audit/audit.rules; then
			report_fail SV-95681r1_rule
		fi
	fi
}





##########
clear_file

SV-90069r1_rule
SV-90071r4_rule
SV-90073r2_rule
SV-90115r2_rule
#SV-90117r3_rule
SV-90199r2_rule 
SV-90121r2_rule
SV-90123r2_rule
SV-90125r3_rule
SV-90129r2_rule
SV-90131r2_rule
SV-90133r2_rule
SV-90135r2_rule
SV-90137r2_rule
SV-90139r2_rule
SV-90143r2_rule
SV-90145r2_rule
SV-90149r1_rule
SV-90151r2_rule
SV-90153r2_rule
SV-90155r2_rule
SV-90157r2_rule
SV-90159r2_rule
SV-90161r2_rule
SV-90163r1_rule
SV-90165r3_rule
#SV-90167r2_rule
SV-90169r2_rule
SV-90237r1_rule
SV-90173r1_rule
#SV-90175r2_rule
SV-90177r1_rule
SV-90179r1_rule
SV-90181r2_rule
#SV-90191r2_rule
SV-90185r2_rule
SV-90187r2_rule
SV-90193r3_rule
SV-90193r3_rule
SV-90195r3_rule
SV-90197r2_rule
SV-90199r3_rule
SV-90215r2_rule
SV-90201r1_rule
SV-90203r3_rule
SV-90205r2_rule
SV-90207r2_rule
SV-90209r1_rule
SV-90211r2_rule
SV-90213r2_rule
SV-90215r2_rule
SV-90221r2_rule
SV-90223r2_rule
SV-90225r2_rule
SV-90227r2_rule
SV-90229r1_rule
SV-90231r1_rule
SV-90233r2_rule
SV-90235r1_rule
SV-90237r1_rule
SV-90239r1_rule

##########

SV-90241r1_rule
SV-90243r1_rule
SV-90245r1_rule
SV-90247r1_rule
SV-90249r1_rule
SV-90251r1_rule
SV-90253r1_rule
SV-90255r2_rule
SV-90263r2_rule
SV-90265r1_rule
SV-90267r2_rule
SV-90269r1_rule
SV-90271r1_rule
SV-90273r2_rule
SV-90275r2_rule
SV-90279r2_rule
SV-90281r2_rule
SV-90283r3_rule
SV-90285r2_rule
SV-90287r2_rule
SV-90289r2_rule
#SV-90291r2_rule
SV-90293r2_rule
SV-90295r2_rule
SV-90297r1_rule
SV-90301r2_rule
SV-90305r2_rule
SV-90307r1_rule
SV-90309r2_rule
SV-90311r1_rule
SV-90313r1_rule
SV-90315r2_rule
SV-90317r2_rule
SV-90319r2_rule

SV-90321r2_rule
SV-90323r2_rule
SV-90325r2_rule
SV-90327r1_rule
SV-90329r2_rule
SV-90333r2_rule
SV-90335r2_rule
SV-90337r2_rule
SV-90339r2_rule
SV-90341r3_rule
SV-90343r3_rule
SV-90345r3_rule
SV-90347r3_rule
SV-90367r3_rule
SV-90369r2_rule
SV-90371r3_rule
SV-90373r3_rule
SV-90375r3_rule
SV-90377r3_rule
SV-90379r3_rule
SV-90387r3_rule
SV-90389r2_rule
SV-90391r2_rule
SV-90393r2_rule
SV-90395r2_rule
SV-90397r2_rule
SV-90399r2_rule
SV-90401r2_rule
SV-90403r2_rule
SV-90405r2_rule
SV-90407r3_rule
SV-90409r3_rule
SV-90411r3_rule
SV-90413r3_rule
SV-90415r3_rule
SV-90417r3_rule
SV-90419r3_rule
SV-90421r3_rule
SV-90423r3_rule
SV-90425r3_rule
SV-90427r3_rule
SV-90429r3_rule
SV-90431r3_rule
SV-90433r3_rule
SV-90435r3_rule
SV-90437r3_rule
SV-90439r3_rule
SV-90441r4_rule
SV-90445r3_rule
SV-90447r3_rule
SV-90449r3_rule
SV-90451r3_rule
SV-90453r3_rule
SV-90455r3_rule
SV-90457r3_rule
SV-90459r3_rule
SV-90461r3_rule
SV-90463r3_rule
SV-90465r3_rule
SV-90467r3_rule
SV-90469r3_rule
SV-90471r3_rule
SV-90473r3_rule
SV-90475r3_rule
SV-90477r2_rule
SV-90479r2_rule
SV-90481r2_rule
SV-90483r2_rule
SV-90485r2_rule
#SV-90487r2_rule
#SV-90489r2_rule
SV-90491r4_rule
SV-90493r2_rule
SV-90497r2_rule
SV-90499r2_rule
SV-90501r2_rule
SV-90503r2_rule
SV-90505r2_rule
SV-90507r2_rule
SV-90509r2_rule
SV-90511r2_rule
SV-90513r2_rule
SV-90515r2_rule
SV-90517r2_rule
SV-90521r2_rule
SV-90523r2_rule
SV-90525r2_rule
SV-90527r2_rule
SV-90529r2_rule
SV-90531r2_rule
SV-90533r2_rule
SV-90535r1_rule
SV-90539r2_rule
SV-90543r2_rule
SV-90545r2_rule
SV-90547r1_rule
SV-90549r2_rule
#SV-90551r2_rule
SV-90553r2_rule
SV-90555r2_rule
SV-90557r2_rule
SV-90559r2_rule
SV-90561r2_rule
SV-90563r2_rule
SV-90565r2_rule
SV-90567r2_rule
SV-90569r2_rule
SV-90583r1_rule
SV-90587r1_rule
SV-90589r1_rule
SV-92701r1_rule
SV-92703r1_rule
SV-95669r1_rule 
SV-95671r1_rule
SV-95673r1_rule
SV-95675r1_rule
SV-95677r1_rule
SV-95681r1_rule

