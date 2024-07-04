apt install -y fail2ban
apt install -y auditd
apt install -y apache2
apt install -y aide
a2enmod headers
apt-get install -y libapache2-modsecurity
apt-get install -y libapache2-mod-security2
apt-get install -y libxml2
apt-get install -y libxml2-dev
apt-get install -y libxml2-utils
apt-get install -y libnss3
ln -sf /usr/lib/x86_64-linux-gnu/libxml2.so.2 /usr/lib/libxml2.so.2
apt install -y libapache2-mod-evasive
debconf-set-selections <<< "postfix postfix/mailname string localhost"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
apt install -y postfix
debconf-set-selections <<< "mysql-server mysql-server/root_password password root" 
debconf-set-selections <<< "mysql-server mysql-server/root_password_again password root"
apt install -y mysql-server
apt install -y ntp
apt install -y vsftpd
apt install -y openssh-server
apt install -y libpam-cracklib
#apt install -y libpam-pwquality
apt install -y ufw
apt install -y samba
apt install -y php7.0
apt install -y libapache2-mod-php7.0
apt install -y php7.0-cli
apt install -y php7.0-common
apt install -y php7.0-mbstring
apt install -y php7.0-gd
apt install -y php7.0-intl
apt install -y php7.0-xml
apt install -y php7.0-mysql
apt install -y php7.0-mcrypt
apt install -y php7.0-zip
rm /var/www/html/info.php
cp ./etc/fail2ban/filter.d/http-get-dos.conf				  /etc/fail2ban/filter.d/http-get-dos.conf		
cp ./etc/fail2ban/jail.local                                              /etc/fail2ban/jail.local
cp ./etc/modprobe.d/hfsplus.conf                                          /etc/modprobe.d/hfsplus.conf
cp ./etc/modprobe.d/cramfs.conf                                           /etc/modprobe.d/cramfs.conf
cp ./etc/modprobe.d/dccp_ipv6.conf                                        /etc/modprobe.d/dccp_ipv6.conf
cp ./etc/modprobe.d/sctp.conf                                             /etc/modprobe.d/sctp.conf
cp ./etc/modprobe.d/blacklist.conf                                        /etc/modprobe.d/blacklist.conf
cp ./etc/modprobe.d/vfat.conf                                             /etc/modprobe.d/vfat.conf
cp ./etc/modprobe.d/jffs2.conf                                            /etc/modprobe.d/jffs2.conf
cp ./etc/modprobe.d/hfs.conf                                              /etc/modprobe.d/hfs.conf
cp ./etc/modprobe.d/appletalk.conf                                        /etc/modprobe.d/appletalk.conf
cp ./etc/modprobe.d/usb-storage.conf                                      /etc/modprobe.d/usb-storage.conf
cp ./etc/modprobe.d/net-pf-31.conf                                        /etc/modprobe.d/net-pf-31.conf
cp ./etc/modprobe.d/dccp.conf                                             /etc/modprobe.d/dccp.conf
cp ./etc/modprobe.d/bluetooth.conf                                        /etc/modprobe.d/bluetooth.conf
cp ./etc/modprobe.d/dccp_ipv4.conf                                        /etc/modprobe.d/dccp_ipv4.conf
cp ./etc/modprobe.d/freevxfs.conf                                         /etc/modprobe.d/freevxfs.conf
cp ./etc/modprobe.d/udf.conf                                              /etc/modprobe.d/udf.conf
cp ./etc/modprobe.d/squashfs.conf                                         /etc/modprobe.d/squashfs.conf
cp ./etc/modprobe.d/rds.conf                                              /etc/modprobe.d/rds.conf
cp ./etc/modprobe.d/tipc.conf                                             /etc/modprobe.d/tipc.conf
cp ./etc/audisp/plugins.d/syslog.conf                                     /etc/audisp/plugins.d/syslog.conf
cp ./etc/bluetooth/main.conf                                              /etc/bluetooth/main.conf
cp ./etc/issue.net                                                        /etc/issue.net
cp ./etc/mysql/mysql.conf.d/mysqld.cnf                                    /etc/mysql/mysql.conf.d/mysqld.cnf
cp ./etc/init/control-alt-delete.conf                                     /etc/init/control-alt-delete.conf
cp ./etc/init/avahi-daemon.override                                       /etc/init/avahi-daemon.override
cp ./etc/init/cups.override                                               /etc/init/cups.override
cp ./etc/init/modemmanager.override                                       /etc/init/modemmanager.override
cp ./etc/init/control-alt-delete.override                                 /etc/init/control-alt-delete.override
cp ./etc/init.d/ntp                                                       /etc/init.d/ntp
cp ./etc/crontab                                                          /etc/crontab
cp ./etc/securetty                                                        /etc/securetty
cp ./etc/pam.d/su                                                         /etc/pam.d/su
cp ./etc/pam.d/login                                                      /etc/pam.d/login
# cp ./etc/pam.d/common-password                                            /etc/pam.d/common-password
# cp ./etc/pam.d/common-account                                             /etc/pam.d/common-account
cp ./etc/hosts.deny                                                       /etc/hosts.deny
cp ./etc/ssl/certs/MyCertificate.crt                                      /etc/ssl/certs/MyCertificate.crt
cp ./etc/ssl/certs/dhparam.pem                                            /etc/ssl/certs/dhparam.pem
cp ./etc/ssl/certs/MyKey.key                                              /etc/ssl/certs/MyKey.key
cp ./etc/denyhosts.conf                                                   /etc/denyhosts.conf
cp ./etc/audit/audit.rules                                                /etc/audit/audit.rules
cp ./etc/audit/auditd.conf                                                /etc/audit/auditd.conf
cp ./etc/vsftpd.conf                                                      /etc/vsftpd.conf
cp ./etc/csh.cshrc                                                        /etc/csh.cshrc
cp ./etc/default/irqbalance                                               /etc/default/irqbalance
cp ./etc/default/useradd                                                  /etc/default/useradd
cp ./etc/default/whoopsie                                                 /etc/default/whoopsie
cp ./etc/default/ufw                                                      /etc/default/ufw
#cp ./etc/default/grub                                                     /etc/default/grub
cp ./etc/default/apport                                                   /etc/default/apport
chattr -i /etc/sysctl.conf
cp ./etc/sysctl.conf                                                      /etc/sysctl.conf
chattr +i /etc/sysctl.conf
cp ./etc/sudoers                                                          /etc/sudoers
cp ./etc/skel/.bashrc                                                     /etc/skel/.bashrc
cp ./etc/apache2/apache2.conf                                             /etc/apache2/apache2.conf
#cp ./etc/apache2/mods-enabled/mpm_event.conf                              /etc/apache2/mods-enabled/mpm_event.conf
cp ./etc/apache2/mods-enabled/dir.conf                                    /etc/apache2/mods-enabled/dir.conf
cp ./etc/apache2/mods-enabled/security2.conf                              /etc/apache2/mods-enabled/security2.conf
cp ./etc/apache2/mods-enabled/reqtimeout.conf                             /etc/apache2/mods-enabled/reqtimeout.conf
cp ./etc/apache2/mods-enabled/evasive.conf                                /etc/apache2/mods-enabled/evasive.conf
cp ./etc/apache2/mods-enabled/ssl.conf                                    /etc/apache2/mods-enabled/ssl.conf
cp ./etc/apache2/conf-enabled/security.conf                               /etc/apache2/conf-enabled/security.conf
cp ./etc/apache2/envvars                                                  /etc/apache2/envvars
cp ./etc/apache2/sites-enabled/000-default.conf                           /etc/apache2/sites-enabled/000-default.conf
cp ./etc/apache2/sites-enabled/default-ssl.conf                           /etc/apache2/sites-enabled/default-ssl.conf
cp ./etc/ssh/sshd_config                                                  /etc/ssh/sshd_config
cp ./etc/motd                                                             /etc/motd
cp ./etc/security/limits.conf                                             /etc/security/limits.conf
cp ./etc/security/access.conf                                             /etc/security/access.conf
cp ./etc/security/pwquality.conf                                          /etc/security/pwquality.conf
cp ./etc/bash.bashrc                                                      /etc/bash.bashrc
cp ./etc/modsecurity/modsecurity.conf                                     /etc/modsecurity/modsecurity.conf
cp ./etc/inittab                                                          /etc/inittab
cp ./etc/ufw/before.rules                                                 /etc/ufw/before.rules
cp ./etc/profile                                                          /etc/profile
cp ./etc/ntp.conf                                                         /etc/ntp.conf
#cp ./etc/fstab                                                            /etc/fstab
cp ./etc/samba/smb.conf                                                   /etc/samba/smb.conf
cp ./etc/php/7.0/fpm/php.ini                                              /etc/php/7.0/fpm/php.ini
cp ./etc/php/7.0/apache2/php.ini                                          /etc/php/7.0/apache2/php.ini
cp ./etc/php/7.0/cli/php.ini                                              /etc/php/7.0/cli/php.ini
cp ./etc/udev/rules.d/85-no-automount.rules                               /etc/udev/rules.d/85-no-automount.rules
cp ./etc/login.defs                                                       /etc/login.defs
cp ./etc/hosts.allow                                                      /etc/hosts.allow
cp ./etc/issue                                                            /etc/issue
cp ./etc/host.conf                                                        /etc/host.conf
#cp ./boot/grub/grub.cfg                                                   /boot/grub/grub.cfg
cp ./lib/lsb/init-functions                                               /lib/lsb/init-functions
cp ./usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf                      /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
cp ./usr/share/lightdm/lightdm.conf.d/50-unity-greeter.conf	          /usr/share/lightdm/lightdm.conf.d/50-unity-greeter.conf	
ufw enable

