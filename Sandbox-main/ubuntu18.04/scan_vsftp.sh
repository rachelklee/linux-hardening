#!/bin/bash

clear_file ()
{
	echo -n > ~/Desktop/vsftp_error.txt
}

report_fail ()
{
	echo $1 $2 | tee -a ~/Desktop/vsftp_error.txt
}

SV-90575r1_rule ()
{
	if ! dpkg -l | grep --quiet vsftpd ; then
		report_fail SV-90575r1_rule notinstalled
	fi
}

########################################################
clear_file

SV-90575r1_rule
