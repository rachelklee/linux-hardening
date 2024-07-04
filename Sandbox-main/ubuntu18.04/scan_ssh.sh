#!/bin/bash

clear_file ()
{
	mkdir -p output
	echo -n > output/ssh_error.txt
}

report_fail ()
{
	echo $1 $2 | tee -a output/ssh_error.txt
}

check_setting_exact()
{
	if ! grep "^[[:space:]]*$2[[:space:]][[:space:]]*$3[[:space:]]*$" $1 > /dev/null ; then
		report_fail "missing : " "$2 $3"
	fi
}

check_setting_contain()
{
	if ! grep "^[[:space:]]*$2.*\<$3\>" $1 > /dev/null ; then
		report_fail "missing : " "$2 $3"
	fi
}

SV-90537r1_rule ()
{
	if ! dpkg -l | grep --quiet openssh-server ; then
		report_fail SV-90537r1_rule notinstalled
		ssh_installed=false
	else
		if ! systemctl status sshd.service | grep --quiet "Active: active"; then
			report_fail SV-90537r1_rule fail
			## fix
			## sudo systemctl enable sshd.service
		fi
		ssh_installed=true
	fi
}

sshd_config_permission ()
{
	file_perm=$( stat -c "%a" /etc/ssh/sshd_config )
	echo $file_perm
	if [ "$file_perm" -ne 640 ]; then
		report_fail sshd_config_permission "permission not equal to 640"
	fi
}

########################################################
clear_file

SV-90537r1_rule
if $ssh_installed == true; then	
	sshd_config_permission
	check_setting_exact /etc/ssh/sshd_config Port 22
	check_setting_exact /etc/ssh/sshd_config Protocol 2
	check_setting_exact /etc/ssh/sshd_config UsePrivilegeSeparation yes
	check_setting_exact /etc/ssh/sshd_config HostKey /etc/ssh/ssh_host_rsa_key
	check_setting_exact /etc/ssh/sshd_config HostKey /etc/ssh/ssh_host_dsa_key
	check_setting_exact /etc/ssh/sshd_config HostKey /etc/ssh/ssh_host_ecdsa_key
	check_setting_exact /etc/ssh/sshd_config HostKey /etc/ssh/ssh_host_ed25519_key 
	check_setting_exact /etc/ssh/sshd_config UsePrivilegeSeparation yes
	check_setting_exact /etc/ssh/sshd_config KeyRegenerationInterval 3600
	check_setting_exact /etc/ssh/sshd_config ServerKeyBits 1024
	check_setting_exact /etc/ssh/sshd_config SyslogFacility AUTH
	check_setting_exact /etc/ssh/sshd_config LogLevel VERBOSE
	check_setting_exact /etc/ssh/sshd_config LoginGraceTime 60
	check_setting_exact /etc/ssh/sshd_config PermitRootLogin no
	check_setting_exact /etc/ssh/sshd_config StrictModes yes
	check_setting_exact /etc/ssh/sshd_config RSAAuthentication yes
	check_setting_exact /etc/ssh/sshd_config PubkeyAuthentication yes
	check_setting_exact /etc/ssh/sshd_config IgnoreRhosts yes
	check_setting_exact /etc/ssh/sshd_config RhostsRSAAuthentication no
	check_setting_exact /etc/ssh/sshd_config HostbasedAuthentication no
	check_setting_exact /etc/ssh/sshd_config IgnoreUserKnownHosts yes
	check_setting_exact /etc/ssh/sshd_config PermitEmptyPasswords no
	check_setting_exact /etc/ssh/sshd_config ChallengeResponseAuthentication no
	check_setting_exact /etc/ssh/sshd_config PasswordAuthentication no
	check_setting_exact /etc/ssh/sshd_config KerberosAuthentication no
	check_setting_exact /etc/ssh/sshd_config GSSAPIAuthentication no
	check_setting_exact /etc/ssh/sshd_config X11Forwarding no
	check_setting_exact /etc/ssh/sshd_config X11DisplayOffset 10
	check_setting_exact /etc/ssh/sshd_config PrintMotd no
	check_setting_exact /etc/ssh/sshd_config PrintLastLog yes
	check_setting_exact /etc/ssh/sshd_config TCPKeepAlive yes
	check_setting_exact /etc/ssh/sshd_config MaxStartups 2
	check_setting_exact /etc/ssh/sshd_config Banner /etc/issue.net
	check_setting_exact /etc/ssh/sshd_config AcceptEnv "LANG LC_\*"
	check_setting_exact /etc/ssh/sshd_config Subsystem "sftp /usr/lib/openssh/sftp-server"
	check_setting_exact /etc/ssh/sshd_config UsePAM yes
	check_setting_exact /etc/ssh/sshd_config RhostsAuthentication no
	check_setting_exact /etc/ssh/sshd_config ClientAliveInterval 300
	check_setting_exact /etc/ssh/sshd_config ClientAliveCountMax 0
	check_setting_exact /etc/ssh/sshd_config AllowTcpForwarding no
	check_setting_exact /etc/ssh/sshd_config PermitUserEnvironment no
	check_setting_exact /etc/ssh/sshd_config UseDNS no
	check_setting_exact /etc/ssh/sshd_config Compression no
	check_setting_exact /etc/ssh/sshd_config MaxAuthTries 4
	check_setting_exact /etc/ssh/sshd_config AuthenticationMethods publickey
	check_setting_exact /etc/ssh/sshd_config FingerprintHash sha512

	check_setting_contain /etc/ssh/sshd_config Ciphers aes128-ctr
	check_setting_contain /etc/ssh/sshd_config Ciphers aes192-ctr
	check_setting_contain /etc/ssh/sshd_config Ciphers aes256-ctr
	check_setting_contain /etc/ssh/sshd_config Ciphers aes128-cbc
	check_setting_contain /etc/ssh/sshd_config Ciphers 3des-cbc
	check_setting_contain /etc/ssh/sshd_config Ciphers aes192-cbc
	check_setting_contain /etc/ssh/sshd_config Ciphers aes256-cbc
	check_setting_contain /etc/ssh/sshd_config MACs hmac-sha2-256
	check_setting_contain /etc/ssh/sshd_config MACs hmac-sha2-512
	check_setting_contain /etc/ssh/sshd_config KexAlgorithms curve25519-sha256@libssh.org
	check_setting_contain /etc/ssh/sshd_config KexAlgorithms ecdh-sha2-nistp521
	check_setting_contain /etc/ssh/sshd_config KexAlgorithms ecdh-sha2-nistp384
	check_setting_contain /etc/ssh/sshd_config KexAlgorithms ecdh-sha2-nistp256
	check_setting_contain /etc/ssh/sshd_config KexAlgorithms diffie-hellman-group-exchange-sha256

	echo scan_ssh done
else
	echo openssh-server is not installed, check skipped
fi
