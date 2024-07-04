#!/bin/bash

clear_file ()
{
	echo -n > ~/Desktop/postfix_error.txt
}

report_fail ()
{
	echo $1 $2 | tee -a ~/Desktop/postfix_error.txt
}

SV-90571r2_rule ()
{
	if ! dpkg -l | grep --quiet postfix; then
		report_fail SV-90571r2_rule notinstalled
	else
		if [ ! -f /etc/postfix/main.cf ]; then
			report_fail SV-90571r2_rule nofile
		else
			if ! grep --quiet "^smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated reject" /etc/postfix/main.cf; then
				report_fail SV-90571r2_rule fail
			fi
		fi
	fi
}

SV-90573r2_rule ()
{
	if [ ! -f /etc/aliases ]; then
		report_fail SV-90573r2_rule nofile
	else
		if ! grep --quiet "^postmaster:    root" /etc/aliases; then
			report_fail SV-90573r2_rule fail
		fi
	fi 
}

########################################################
clear_file

SV-90571r2_rule
SV-90573r2_rule
