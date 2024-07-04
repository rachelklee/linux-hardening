#!/bin/bash
	mkdir -p output

	sort -u /var/lib/dpkg/info/*.list -o output/dpkgfiles.txt

	find /bin -type f | sort -u -o output/binfiles
	comm -23 output/binfiles output/dpkgfiles.txt | tee output/dpkg_suspicious_file.txt
	rm output/binfiles

	find /sbin -type f | sort -u -o output/sbinfiles
	comm -23 output/sbinfiles output/dpkgfiles.txt | tee -a output/dpkg_suspicious_file.txt
	rm output/sbinfiles

	find /usr/bin -type f | sort -u -o output/usrbinfiles
	comm -23 output/usrbinfiles output/dpkgfiles.txt | tee -a output/dpkg_suspicious_file.txt
	rm output/usrbinfiles

	find /usr/sbin -type f | sort -u -o output/usrsbinfiles
	comm -23 output/usrsbinfiles output/dpkgfiles.txt | tee -a output/dpkg_suspicious_file.txt
	rm output/usrsbinfiles

	find /usr/local/bin -type f | sort -u -o output/usrlocalbinfiles
	comm -23 output/usrlocalbinfiles output/dpkgfiles.txt | tee -a output/dpkg_suspicious_file.txt
	rm output/usrlocalbinfiles

	find /usr/local/sbin -type f | sort -u -o output/usrlocalsbinfiles
	comm -23 output/usrlocalsbinfiles output/dpkgfiles.txt | tee -a output/dpkg_suspicious_file.txt
	rm output/usrlocalsbinfiles

	find /etc/cron.d -type f | sort -u -o output/etccrondfiles
	comm -23 output/etccrondfiles output/dpkgfiles.txt | tee -a output/dpkg_suspicious_file.txt
	rm output/etccrondfiles

	find /etc/cron.hourly -type f | sort -u -o output/etccronhourlyfiles
	comm -23 output/etccronhourlyfiles output/dpkgfiles.txt | tee -a output/dpkg_suspicious_file.txt
	rm output/etccronhourlyfiles

	find /etc/cron.daily -type f | sort -u -o output/etccrondailyfiles
	comm -23 output/etccrondailyfiles output/dpkgfiles.txt | tee -a output/dpkg_suspicious_file.txt
	rm output/etccrondailyfiles

	find /etc/cron.monthly -type f | sort -u -o output/etccronmonthlyfiles
	comm -23 output/etccronmonthlyfiles output/dpkgfiles.txt | tee -a output/dpkg_suspicious_file.txt
	rm output/etccronmonthlyfiles

	find /etc/cron.weekly -type f | sort -u -o output/etccronweeklyfiles
	comm -23 output/etccronweeklyfiles output/dpkgfiles.txt | tee -a output/dpkg_suspicious_file.txt
	rm output/etccronweeklyfiles

	find /var/mail -type f | sort -u -o output/varmailfiles
	comm -23 output/varmailfiles output/dpkgfiles.txt | tee -a output/dpkg_suspicious_file.txt
	rm output/varmailfiles

	find /var/spool/anacron -type f | sort -u -o output/varspoolanacronfiles
	comm -23 output/varspoolanacronfiles output/dpkgfiles.txt | tee -a output/dpkg_suspicious_file.txt
	rm output/varspoolanacronfiles

	find /var/spool/cron -type f | sort -u -o output/varspoolcronfiles
	comm -23 output/varspoolcronfiles output/dpkgfiles.txt | tee -a output/dpkg_suspicious_file.txt
	rm output/varspoolcronfiles

