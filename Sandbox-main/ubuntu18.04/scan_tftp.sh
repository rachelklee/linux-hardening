#!/bin/bash

clear_file ()
{
	echo -n > ~/Desktop/tftp_error.txt
}

report_fail ()
{
	echo $1 $2 | tee -a ~/Desktop/tftp_error.txt
}

SV-90577r1_rule ()
{
	if ! dpkg -l | grep --quiet tftpd-hpa ; then
		report_fail SV-90577r1_rule notinstalled
	elif ! dpkg -l | grep --quiet tftpd ; then
		report_fail SV-90577r1_rule notinstalled
	fi
}

SV-90579r1_rule ()
{
	if [ ! -f /etc/default/tftpd-hpa ]; then
		report_fail SV-90579r1_rule nofile
	else
		if ! grep --quiet --no-messages "^TFTP_OPTIONS=\"--secure\"" /etc/default/tftpd-hpa; then
			report_fail SV-90579r1_rule fail1
		fi
	fi
}

########################################################
clear_file

SV-90577r1_rule
SV-90579r1_rule
