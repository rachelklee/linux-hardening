#!/bin/bash
	mkdir -p ~/Desktop/output

	apt install file -y 2&> /dev/null
	apt install binutils -y 2&> /dev/null
	
	find / -type f | tee ~/Desktop/output/allfiles.txt
	file -i -N -f ~/Desktop/output/allfiles.txt | tee ~/Desktop/output/filetype.txt
	
	grep -i ": audio" ~/Desktop/output/filetype.txt | tee ~/Desktop/output/audiofiles
	grep -i ": video" ~/Desktop/output/filetype.txt | tee ~/Desktop/output/videofiles
	grep -i ": image" ~/Desktop/output/filetype.txt | tee ~/Desktop/output/imagefiles
