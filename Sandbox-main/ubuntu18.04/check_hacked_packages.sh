#!/bin/bash
	if ! dpkg -s debsums > /dev/null 2>&1 ; then
		echo install debsums first
	else
		mkdir -p output
		apt install debsums -y 2&>/dev/null

		debsums_init
		debsums --change 2>/dev/null | grep -v pyc | tee output/hacked_package.txt

		debsums -a bash | grep FAILED | tee output/hacked_bash_file.txt
	fi
