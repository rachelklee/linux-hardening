#!/bin/bash

clear_file ()
{
	echo -n > ~/Desktop/apache2_error.txt
}

report_fail ()
{
	echo $1 $2 | tee -a ~/Desktop/apache2_error.txt
}

SV-36309r2_rule ()
{
	if [ ! -f /etc/apache2/mods-enabled/mime.conf ]; then
		report_fail SV-36309r2_rule nofile_/etc/apache2/modes-enabled/mime.conf
		# fix
		# a2enmod mime
	else
		mimeshell=$(grep -A10000 "<IfModule" /etc/apache2/mods-enabled/mime.conf | grep -B100000 "</IfModule"|grep "^[[:space:]]*Action" | awk '{$1=""; print $0}')
		if echo $mimeshell | grep --quiet /bin/csh ; then
			report_fail SV-36309r2_rule fail_Action_should_not_add_/bin/csh
		elif echo $mimeshell | grep --quiet /bin/sh ; then
			report_fail SV-36309r2_rule fail_Action_should_not_add_/bin/sh
		elif echo $mimeshell | grep --quiet /bin/tcsh ; then
			report_fail SV-36309r2_rule fail_Action_should_not_add_/bin/tcsh
		elif echo $mimeshell | grep --quiet /bin/bash ; then
			report_fail SV-36309r2_rule fail_Action_should_not_add_/bin/bash
		fi
	
		mimeshell=$(grep -A10000 "<IfModule" /etc/apache2/mods-enabled/mime.conf | grep -B100000 "</IfModule"|grep "^[[:space:]]*AddHandler" | awk '{$1=""; print $0}')
		if echo $mimeshell | grep --quiet /bin/csh ; then
			report_fail SV-36309r2_rule fail_AddHandler_should_not_add_/bin/csh
		elif echo $mimeshell | grep --quiet /bin/sh ; then
			report_fail SV-36309r2_rule fail_AddHandler_should_not_add_/bin/sh
		elif echo $mimeshell | grep --quiet /bin/tcsh ; then
			report_fail SV-36309r2_rule fail_AddHandler_should_not_add_/bin/tcsh
		elif echo $mimeshell | grep --quiet /bin/bash ; then
			report_fail SV-36309r2_rule fail_AddHandler_should_not_add_/bin/bash
		fi
	fi
}

SV-6930r2_rule ()
{
	if [ ! -f /etc/apache2/sites-available/000-default.conf ]; then
		report_fail SV-6930r2_rule nofile_/etc/apache2/sites-available/000-default.conf
	else
		DocumentRoot=$(grep DocumentRoot /etc/apache2/sites-enabled/000-default.conf | awk '{print $2}')
		if find $DocumentRoot -name "*.bak" | grep --quiet ".*"; then
			report_fail SV-6930r2_rule fail1
		fi
		if find $DocumentRoot -name "*.*~" | grep --quiet ".*"; then
			report_fail SV-6930r2_rule fail2
		fi
		if find $DocumentRoot -name "*.old" | grep --quiet ".*"; then
			report_fail SV-6930r2_rule fail3
		fi
	fi
}

SV-32788r1_rule ()
{
	report_fail SV-32788r1_rule check_stig
}

SV-32957r1_rule ()
{
	if ! grep --quiet "DocumentRoot" /etc/apache2/sites-enabled/*; then
		report_fail SV-32957r1_rule nofile
	else
		DocumentRoot=$(grep DocumentRoot /etc/apache2/sites-enabled/* | awk '{print $2}')
		if find $DocumentRoot -type l | grep --quiet "" ; then
			report_fail SV-32957r1_rule fail1
		fi
	fi
}

SV-32956r3_rule ()
{
	report_fail SV-32956r3_rule check_stig
}

SV-32932r2_rule ()
{
	report_fail SV-32932r2_rule not_use
}

SV-32935r1_rule ()
{
	report_fail SV-32935r1_rule not_use
}

SV-36441r2_rule ()
{
	if ! apt list apache2 2> /dev/null| grep --quiet --word-regexp installed; then
		report_fail notinstalled_apache2
	else
		if ! apache2 -v | grep --quiet 2.4.18; then
			report_fail fail1
		fi
	fi
}

SV-36456r2_rule ()
{
	report_fail SV-36456r2_rule check_stig
}

SV-32955r2_rule ()
{
	report_fail SV-32955r2_rule check_stig
}

SV-32948r2_rule ()
{
	report_fail SV-32948r2_rule check_stig
}

SV-36478r2_rule ()
{
	for filename in $(find / -name htpasswd 2>/dev/null); do
		if [ $(stat -c "%a" $filename) -gt 550 ]; then
			report_fail SV-36478r2_rule fail_permission_${filename}
		fi
		if ! stat -c "%U" $filename | grep --quiet root; then
			report_fail SV-36478r2_rule fail_owner_not_root_${filename}
		fi
	done
}

SV-6880r1_rule ()
{
	for filename in $(find / -name ".htaccess" 2>/dev/null); do
		if ! stat -c "%U %G" $filename | grep --quiet "root root"; then
			report_fail SV-6880r1_rule fail_owner_not_root_${filename}
		fi
		if [ $(stat -c "%a" $filename) -gt 660 ]; then
			report_fail SV-6880r1_rule fail_permission_${filename}
		fi
	done

	filename=$(find / -name "apache2.conf" 2>/dev/null)
	if [ ! -z $filename ]; then
		if ! stat -c "%U %G" $filename | grep --quiet "root root"; then
			report_fail SV-6880r1_rule fail_${filename}_owner_not_root
		fi
		if [ $(stat -c "%a" $filename) -gt 660 ]; then
			report_fail SV-6880r1_rule fail_permission_${filename}
		fi
	fi
}	

SV-32951r1_rule ()
{
	report_fail SV-32951r1_rule check_stig
}

SV-32938r1_rule ()
{
	if [ ! -f /etc/apache2/sites-available/000-default.conf ]; then
		report_fail SV-32938r1_rule nofile_/etc/apache2/sites-available/000-default.conf
	else
		DocumentRoot=$(grep DocumentRoot /etc/apache2/sites-enabled/000-default.conf | awk '{print $2}')
		if [ $(stat -c "%a" $DocumentRoot) -gt 750 ]; then
			report_fail SV-32938r1_rule fail_permission_${DocumentRoot}
		fi

		for filename in ${DocumentRoot}/*; do
			if [ $(stat -c "%a" $filename) -gt 640 ]; then
				report_fail SV-32938r1_rule fail_permission_${filename}
			fi
		done
	fi 
}

SV-32937r1_rule () {
	report_fail SV-32937r1_rule check_stig
}

SV-32927r2_rule ()
{
	report_fail SV-32927r2_rule not_use
}

SV-32964r2_rule ()
{
	report_fail SV-32964r2_rule not_use
}

SV-32950r1_rule ()
{
	report_fail SV-32950r1_rule not_use
}

SV-36672r1_rule ()
{
	if [ ! -f /etc/apache2/conf-enabled/security.conf ]; then
		report_fail SV-36672r1_rule nofile_/etc/apach2/conf-enabled/security.conf
	else
		if ! grep --quiet "^ServerTokens Prod" /etc/apache2/conf-enabled/security.conf; then
			report_fail SV-36672r1_rule fail1
		fi
	fi
}

SV-32969r2_rule ()
{
	report_fail SV-32969r2_rule not_use
}

SV-32936r1_rule ()
{
	if [ ! -f /etc/apache2/mods-enabled/ssl.conf ]; then
		report_fail SV-32936r1_rule nofile_/etc/apache2/mods-enabled/ssl.conf
		# fix
		# sudo a2enmod ssl
	fi
}

SV-32933r1_rule ()
{
	report_fail SV-32933r1_rule check_stig
}

SV-32954r2_rule ()
{
	report_fail SV-32933r1_rule not_use
}

SV-32977r1_rule ()
{
	if [ ! -f /etc/apache2/apache2.conf ]; then
		report_fail SV-32977r1_rule nofile_/etc/apache2/apache2.conf
	else
		Timeout=$(grep --word-regexp "^Timeout" /etc/apache2/apache2.conf | awk '{print $2}')
		if [ -z $Timeout ]; then
			report_fail SV-32977r1_rule fail_Timeout_not_set
		elif [ $Timeout -gt 300 ]; then
			report_fail SV-32977r1_rule fail_Timeout_bigger_than_300
		fi
	fi
}

SV-32844r2_rule ()
{
	if [ ! -f /etc/apache2/apache2.conf ]; then
		report_fail SV-32844r2_rule nofile_/etc/apache2/apache2.conf
	else
		if ! grep --quiet "^KeepAlive On" /etc/apache2/apache2.conf; then
			report_fail SV-32844r2_rule fail1
		fi
	fi
}

SV-32877r1_rule ()
{
	if [ ! -f /etc/apache2/apache2.conf ]; then
		report_fail SV-32877r1_rule nofile_/etc/apache2/apache2.conf
	else
		KeepAliveTimeout=$(grep --word-regexp "^KeepAliveTimeout" /etc/apache2/apache2.conf | awk '{print $2}')
		if [ -z $KeepAliveTimeout ]; then
			report_fail SV-32877r1_rule fail_KeepAliveTimeout_not_set
		elif [ $KeepAliveTimeout -gt 15 ]; then
			report_fail SV-32877r1_rule fail_KeepAliveTimeout_greater_than_15
		fi
	fi
}

SV-36645r2_rule ()
{
	if [ ! -f /etc/apache2/mods-enabled/mpm_prefork.conf ]; then
		report_fail SV-36645r2_rule nofile_/etc/apache2/mods-enabled/mpm_prefork.conf
		# fix
		# a2dismod mpm_event
		# a2enmod mpm_prefork
	else
		StartServers=$(grep -A10000 "<IfModule" /etc/apache2/mods-enabled/mpm_prefork.conf | grep -B100000 "</IfModule"|grep "^[[:space:]]*StartServers" | awk '{print $2}')
		if [ ! -z $StartServers ]; then
			if ! [[ $StartServers -ge 5 && $StartServers -le 10 ]]; then
				report_fail SV-36645r2_rule fail_StartServers_not_between_5_10
			fi
		else
				report_fail SV-36645r2_rule fail_StartServers_not_between_5_10
		fi
	fi
}

SV-36646r2_rule ()
{
	if [ ! -f /etc/apache2/mods-enabled/mpm_prefork.conf ]; then
		report_fail SV-36646r2_rule nofile_/etc/apache2/mods-enabled/mpm_prefork.conf
		# fix
		# a2dismod mpm_event
		# a2enmod mpm_prefork
	else
		MinSpareServers=$(grep -A10000 "<IfModule" /etc/apache2/mods-enabled/mpm_prefork.conf | grep -B100000 "</IfModule"|grep "^[[:space:]]*MinSpareServers" | awk '{print $2}')
		if [ ! -z $MinSpareServers ]; then
			if ! [[ $MinSpareServers -ge 5 && $MinSpareServers -le 10 ]]; then
				report_fail SV-36646r2_rule fail_MinSpareServers_not_between_5_10
			fi
		else
				report_fail SV-36646r2_rule fail_MinSpareServers_not_between_5_10
		fi
	fi
}

SV-36648r2_rule ()
{
	if [ ! -f /etc/apache2/mods-enabled/mpm_prefork.conf ]; then
		report_fail SV-36648r2_rule nofile_/etc/apache2/mods-enabled/mpm_prefork.conf
		# fix
		# a2dismod mpm_event
		# a2enmod mpm_prefork
	else
		MaxSpareServers=$(grep -A10000 "<IfModule" /etc/apache2/mods-enabled/mpm_prefork.conf | grep -B100000 "</IfModule"|grep "^[[:space:]]*MaxSpareServers" | awk '{print $2}')
		if [ ! -z $MaxSpareServers ]; then
			if [[ $MaxSpareServers -gt 10 ]]; then
				report_fail SV-36648r2_rule fail_MaxSpareServers_greater_than_10
			fi
		else
				report_fail SV-36648r2_rule fail_MaxSpareServers_greater_than_10
		fi
	fi
}

SV-36649r2_rule ()
{
	if [ ! -f /etc/apache2/mods-enabled/mpm_prefork.conf ]; then
		report_fail SV-36649r2_rule nofile_/etc/apache2/mods-enabled/mpm_prefork.conf
		# fix
		# a2dismod mpm_event
		# a2enmod mpm_prefork
	else
		MaxClients=$(grep -A10000 "<IfModule" /etc/apache2/mods-enabled/mpm_prefork.conf | grep -B100000 "</IfModule"|grep "^[[:space:]]*MaxClients" | awk '{print $2}')
		if [ ! -z $MaxClients ]; then
			if [[ $MaxClients -gt 256 ]]; then
				report_fail SV-36649r2_rule fail_MaxClients_greater_than_256
			fi
		else
				report_fail SV-36649r2_rule fail_MaxClients_greater_than_256
		fi
	fi
}

SV-32763r1_rule ()
{
	if [ ! -d /etc/apache2/conf-enabled ]; then
		report_fail SV-32763r1_rule nodirectory_/etc/apache2/conf-enabled
	else
		for filename in $(grep -l ExecCGI /etc/apache2/conf-enabled/*); do
			if grep -A10000 "<IfModule" $filename | grep -B100000 "</IfModule" | grep "^[[:space:]]*Options" | grep --quiet "[[:space:]]ExecCGI"; then
				report_fail SV-32763r1_rule fail_${filename}_should_be+ExecCGI
			fi
		done
	fi
}

SV-40129r1_rule ()
{
	report_fail SV-40129r1_rule check_stig
}

SV-32753r1_rule ()
{
	report_fail SV-32753r1_rule check_stig
}

SV-32755r1_rule ()
{
	report_fail SV-32755r1_rule check_stig
}

SV-32756r1_rule ()
{
	report_fail SV-32756r1_rule check_stig
}

SV-32757r1_rule ()
{
	report_fail SV-32757r1_rule check_stig
}

SV-32766r2_rule ()
{
	report_fail SV-32766r2_rule check_stig
}

SV-32768r2_rule ()
{
	report_fail SV-32768r2_rule check_stig
}

SV-33215r1_rule ()
{
	report_fail SV-33215r1_rule check_stig
}

SV-33216r1_rule ()
{
	if ! apache2ctl -V 1>/dev/null 2>/dev/null; then
		report_fail SV-33216r1_rule fail_notinstalled_apache2
	else
		if apache2ctl -M 2>/dev/null | grep --quiet dav_module; then
			report_fail SV-33216r1_rule fail_dav_module_not_disabled
		fi
		if apache2ctl -M 2>/dev/null | grep --quiet dav_fs_module; then
			report_fail SV-33216r1_rule fail_dav_fs_module_not_disabled
		fi
		if apache2ctl -M 2>/dev/null | grep --quiet dav_lock_module; then
			report_fail SV-33216r1_rule fail_dav_lock_module_not_disabled
		fi
	fi
}

SV-33218r1_rule ()
{
	if ! apache2ctl -V 1>/dev/null 2>/dev/null; then
		report_fail SV-33218r1_rule fail_notinstalled_apache2
	else
		if apache2ctl -M 2>/dev/null | grep --quiet info_module; then
			report_fail SV-33218r1_rule fail_info_module_not_disabled
		fi
		if apache2ctl -M 2>/dev/null | grep --quiet status_module; then
			report_fail SV-33218r1_rule fail_status_module_not_disabled
		fi
	fi
}

SV-33220r2_rule ()
{
	if ! apache2ctl -V 1>/dev/null 2>/dev/null; then
		report_fail SV-33220r1_rule fail_notinstalled_apache2
	else
		if apache2ctl -M 2>/dev/null | grep --quiet proxy_module; then
			report_fail SV-33220r1_rule fail_proxy_module_not_disabled
		fi
		if apache2ctl -M 2>/dev/null | grep --quiet proxy_ajp_module; then
			report_fail SV-33220r1_rule fail_proxy_ajp_module_not_disabled
		fi
		if apache2ctl -M 2>/dev/null | grep --quiet proxy_balancer_module; then
			report_fail SV-33220r1_rule fail_proxy_balancer_module_not_disabled
		fi
		if apache2ctl -M 2>/dev/null | grep --quiet proxy_connect_module; then
			report_fail SV-33220r1_rule fail_proxy_connect_module_not_disabled
		fi
		if apache2ctl -M 2>/dev/null | grep --quiet proxy_express_module; then
			report_fail SV-33220r1_rule fail_proxy_express_module_not_disabled
		fi
		if apache2ctl -M 2>/dev/null | grep --quiet proxy_fcgi_module; then
			report_fail SV-33220r1_rule fail_proxy_fcgi_module_not_disabled
		fi
		if apache2ctl -M 2>/dev/null | grep --quiet proxy_fdpass_module; then
			report_fail SV-33220r1_rule fail_proxy_fdpass_module_not_disabled
		fi
		if apache2ctl -M 2>/dev/null | grep --quiet proxy_ftp_module; then
			report_fail SV-33220r1_rule fail_proxy_ftp_module_not_disabled
		fi
		if apache2ctl -M 2>/dev/null | grep --quiet proxy_html_module; then
			report_fail SV-33220r1_rule fail_proxy_html_module_not_disabled
		fi
		if apache2ctl -M 2>/dev/null | grep --quiet proxy_http_module; then
			report_fail SV-33220r1_rule fail_proxy_http_module_not_disabled
		fi
		if apache2ctl -M 2>/dev/null | grep --quiet proxy_scgi_module; then
			report_fail SV-33220r1_rule fail_proxy_scgi_module_not_disabled
		fi
		if apache2ctl -M 2>/dev/null | grep --quiet proxy_wstunnel_module; then
			report_fail SV-33220r1_rule fail_proxy_wstunnel_module_not_disabled
		fi
	fi
}

SV-33221r1_rule ()
{
	if ! apache2ctl -V 1>/dev/null 2>/dev/null; then
		report_fail SV-33221r1_rule fail_notinstalled_apache2
	else
		if apache2ctl -M 2>/dev/null | grep --quiet userdir_module; then
			report_fail SV-33221r1_rule fail_userdir_module_not_disabled
		fi
	fi
}

SV-33223r2_rule ()
{
	report_fail SV-33223r2_rule check_stig
}

SV-33226r1_rule ()
{
	if [ ! -f /etc/apache2/apache2.conf ]; then
		report_fail SV-33226r1_rule nofile_/etc/apache2/apache2.conf
	else
		if ! grep -A100000 "^<Directory />" /etc/apache2/apache2.conf|grep -B100000 "^</Directory>" -m1|grep --quiet "^[[:space:]]*Require all denied"; then
			report_fail SV-33226r1_rule fail_not_set_Require_all_denied
		fi
	fi
}

SV-33213r1_rule ()
{
	if [ ! -f /etc/apache2/apache2.conf ]; then
		report_fail SV-33213r1_rule nofile_/etc/apache2/apache2.conf
	else
		if ! grep -A100000 "^<Directory />" /etc/apache2/apache2.conf | grep -m1 -B1000000 "^</Directory>" | grep --quiet "^[[:space:]]*Options None"; then
			report_fail SV-33213r1_rule fail_not_set_Options_None
		fi

		if ! grep -A100000 "^<Directory />" /etc/apache2/apache2.conf | grep -m1 -B1000000 "^</Directory>" | grep --quiet ""; then
			report_fail SV-33213r1_rule fail_no_definition_for_root_directory
		else
			if grep -A100000 "^<Directory />" /etc/apache2/apache2.conf | grep -m1 -B1000000 "^</Directory>" | grep --quiet "[[:space:]]Allow[[:space:]]"; then
				report_fail SV-33213r1_rule fail_defined_Allow_for_root_directory
			fi
		fi
	fi
}

SV-33227r1_rule ()
{
	if [ ! -f /etc/apache2/conf-enabled/security.conf ]; then
		report_fail SV-33227r1_rule nofile_/etc/apache2/conf-enabled/security.conf
	else
		if ! grep --quiet "^TraceEnable Off" /etc/apache2/conf-enabled/security.conf; then
			report_fail SV-33227r1_rule fail_not_defined_TraceEnable_Off
		fi

		if grep "^[[:space:]]*TraceEnable" /etc/apache2/apache2.conf | grep --invert-match Off | grep --quiet ""; then
			report_fail SV-33227r1_rule fail_not_defined_TraceEnable_Off
		fi

		for filename in /etc/apache2/conf-enabled/*; do
			if grep "^[[:space:]]*TraceEnable" $filename | grep --invert-match Off | grep ""; then
				report_fail SV-33227r1_rule fail_TraceEnable_is_not_Off
			fi
		done
	fi
}

SV-33228r1_rule ()
{
	if [ ! -f /etc/apache2/ports.conf ]; then
		report_fail SV-33228r1_rule nofile_/etc/apache2/ports.conf
	else
		if grep "^[[:space:]]*Listen" /etc/apache2/ports.conf | grep --invert-match : | grep --quiet ""; then
			report_fail SV-33228r1_rule fail_no_IP_address_for_Listen
		fi
	fi
}

SV-33229r1_rule ()
{
	if [ ! -d /etc/apache2/conf-enabled ]; then
		report_fail SV-33229r1_rule nodirectory_/etc/apache2/conf-enabled
	else
		if grep "^[[:space:]]*ScriptAlias[[:space:]]*$" /etc/apache2/conf-enabled/* ; then
			report_fail SV-33229r1_rule fail_no_directory_defined_for_ScriptAlias
		fi
	fi
}

SV-33219r1_rule ()
{
	if ! apache2ctl -V 1>/dev/null 2>/dev/null; then
		report_fail SV-33219r1_rule fail_notinstalled_apache2
	else
		if apache2ctl -M 2>/dev/null | grep --quiet autoindex_module; then
			report_fail SV-33219r1_rule fail_autoindex_module_not_disabled
		fi
	fi
}

SV-33232r1_rule ()
{
	if [ ! -f /etc/apache2/apache2.conf ]; then
		report_fail SV-33232r1_rule nofile_/etc/apache2/apache2.conf
	else
		if ! sed -n '/^<Directory \/>/,/^<\/Directory>/p' /etc/apache2/apache2.conf | grep --quiet ""; then
			report_fail SV-33232r1_rule fail_root_directory_is_not_defined
		else
			if ! sed -n '/^<Directory \/>/,/^<\/Directory>/p' /etc/apache2/apache2.conf | grep --quiet "^[[:space:]]*AllowOverride None"; then
				report_fail SV-33232r1_rule fail_not_defined_AllowOverride_None
			fi

			if sed -n '/^<Directory \/>/,/^<\/Directory>/p' /etc/apache2/apache2.conf | grep "^[[:space:]]Allow[[:space:]]" ; then
				report_fail SV-33232r1_rule fail_Allow_defined
			fi
		fi
	fi
}

SV-33236r1_rule ()
{
	report_fail SV-33236r1_rule check_stig
}

SV-75159r1_rule ()
{
	if [ ! -f /etc/apache2/mods-enabled/ssl.conf ]; then
		report_fail SV-75159r1_rule nofile_/etc/apache2/mods-enabled/ssl.conf
	else
		if ! sed -n '/^<IfModule mod_ssl.c>/,/^<\/IfModule>/p' /etc/apache2/mods-enabled/ssl.conf | grep --quiet ""; then
			report_fail SV-75159r1_rule fail_IfModule_no_defined
		else
			if ! sed -n '/^<IfModule mod_ssl.c>/,/^<\/IfModule>/p' /etc/apache2/mods-enabled/ssl.conf | grep "^[[:space:]]*SSLCipherSuite" | grep --quiet "\!EXP";then
				report_fail SV-75719r1_rule fail_!EXPORT_not_defined_for_SSLCipherSuite
			fi
		fi
	fi
}

########################################################
clear_file

SV-36309r2_rule
SV-6930r2_rule
SV-32788r1_rule
SV-32957r1_rule
SV-32956r3_rule
SV-32932r2_rule
SV-32935r1_rule
SV-36441r2_rule
SV-36456r2_rule
SV-36456r2_rule
SV-32955r2_rule
SV-36478r2_rule
SV-6880r1_rule
SV-32951r1_rule
SV-32938r1_rule
SV-32937r1_rule
SV-32927r2_rule
SV-32964r2_rule
SV-32950r1_rule
SV-36672r1_rule
SV-32969r2_rule
SV-32936r1_rule
SV-32933r1_rule
SV-32954r2_rule
SV-32977r1_rule
SV-32844r2_rule
SV-32877r1_rule
SV-36645r2_rule
SV-36646r2_rule
SV-36648r2_rule
SV-36649r2_rule
SV-32763r1_rule
SV-40129r1_rule
SV-32753r1_rule
SV-32755r1_rule
SV-32756r1_rule
SV-32757r1_rule
SV-32766r2_rule
SV-32768r2_rule
SV-33215r1_rule
SV-33216r1_rule
SV-33218r1_rule
SV-33220r2_rule
SV-33221r1_rule
SV-33223r2_rule
SV-33226r1_rule
SV-33213r1_rule
SV-33227r1_rule
SV-33228r1_rule
SV-33229r1_rule
SV-33219r1_rule
SV-33232r1_rule
SV-33236r1_rule
SV-75159r1_rule
