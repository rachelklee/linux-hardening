#!/bin/bash
	mkdir -p output

	sudo dpkg --get-selections | grep -v deinstall | grep -v ^lib | grep -v ^xserver-xorg | grep -v ^python | grep -v ^linux | grep -v ^font > output/installedpackage.txt
	
