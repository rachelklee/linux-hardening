#!/bin/bash 
find_replace_insert ()
{
    if [ ! -e "$1" ]; then
        sudo touch $1
    fi
    search_string="^(^|[[:space:]]*)(${2//\//\\/})($|[[:space:]])"
    value_string=${3//\//\\/}
     sudo grep -E "$search_string" $1 \
     && sudo sed -E "s/$search_string.*/\1\2$value_string/g" -i $1 \
    || sudo echo $2$3 |sudo tee -a $1
}

####################################################

init()
{
    package_check="good"

    # install coreutil if not available
    if dpkg -s coreutils > /dev/null 2>&1 ; then
        :
    else
        echo "# install coreutils before running check_user.sh"
        echo "apt install -y coreutils"
        package_check="error"
    fi

    # install whois if not available
    if dpkg -s whois > /dev/null 2>&1 ; then
        :
    else
        echo "# install whois before running check_user.sh"
        echo "apt install -y whois"
        package_check="error"
    fi

    if [ "$package_check" == "error" ]; then
        exit 0
    fi

    mkdir -p output
    truncate -s 0 output/active_users.txt
    truncate -s 0 output/active_groups.txt
    truncate -s 0 output/check_user_error.txt
    # fix integrity of /etc/passwd and /etc/shadow
    pwconv
    # fix integrity of /etc/group and /etc/gshadow
    grpconv
}

get_active_users_and_groups ()
{
    echo check active users and groups
    echo '1. check /var/lib/dpkg/info/*.preinst for the following unknown users' | sudo tee output/active_users.txt
    echo '2. check /var/lib/dpkg/info/*.postinst for the following unknown users' | sudo tee -a output/active_users.txt
    echo '1. check /var/lib/dpkg/info/*.preinst for the following unknown group' | sudo tee output/active_groups.txt
    echo '2. check /var/lib/dpkg/info/*.postinst for the following unknown group' | sudo tee -a output/active_groups.txt

    list_of_active_users=( $(sudo cat /etc/passwd | cut -d':' -f 1 ) )
    
    for i in "${list_of_active_users[@]}"
    do
        echo "$i -----------> unknown" >> output/active_users.txt
    done

    list_of_active_group=( $(sudo cat /etc/group | cut -d':' -f 1 ) )
    for i in "${list_of_active_group[@]}"
    do
        echo $i "-----------> unknown" >> output/active_groups.txt
    done
}

filter_users_and_groups_from_package ()
{
    list_of_known_users=()
    check_user_shell vboxadd /bin/false
    add_to_known_group vboxsf

    if dpkg -s base-passwd &> /dev/null; then
        check_user_shell root /bin/bash
        check_user_shell daemon disable
        check_user_shell bin disable
        check_user_shell sys disable
        check_user_shell sync /bin/sync
        check_user_shell games disable
        check_user_shell man disable
        check_user_shell lp disable
        check_user_shell mail disable
        check_user_shell news disable
        check_user_shell uucp disable
        check_user_shell proxy disable
        check_user_shell www-data disable
        check_user_shell backup disable
        check_user_shell list disable
        check_user_shell irc disable
        check_user_shell gnats disable
        check_user_shell nobody disable

        add_to_known_group root
        add_to_known_group daemon
        add_to_known_group bin
        add_to_known_group sys
        add_to_known_group adm
        add_to_known_group tty
        add_to_known_group disk
        add_to_known_group lp
        add_to_known_group mail
        add_to_known_group news
        add_to_known_group uucp
        add_to_known_group man
        add_to_known_group proxy
        add_to_known_group kmem
        add_to_known_group dialout
        add_to_known_group fax
        add_to_known_group voice
        add_to_known_group cdrom
        add_to_known_group floppy
        add_to_known_group tape
        add_to_known_group sudo
        add_to_known_group audio
        add_to_known_group dip
        add_to_known_group www-data
        add_to_known_group backup
        add_to_known_group operator
        add_to_known_group list
        add_to_known_group irc
        add_to_known_group src
        add_to_known_group gnats
        add_to_known_group shadow
        add_to_known_group utmp
        add_to_known_group video
        add_to_known_group sasl
        add_to_known_group plugdev
        add_to_known_group staff
        add_to_known_group games
        add_to_known_group users
        add_to_known_group nogroup
    fi 

    if dpkg -s apt &> /dev/null; then
        check_user_shell _apt disable

    fi

    if dpkg -s gnome-initial-setup &> /dev/null; then
        check_user_shell gnome-initial-setup disable

        add_to_known_group gnome-initial-setup
    fi

    if dpkg -s uuid-runtime &> /dev/null; then
        check_user_shell uuidd disable

    fi

    if dpkg -s ntp &> /dev/null; then
        check_user_shell ntp disable

    fi

    if dpkg -s sane-utils &> /dev/null; then
        check_user_shell saned disable

    fi

    if dpkg -s systemd &> /dev/null; then
        check_user_shell systemd-network disable
        check_user_shell systemd-resolve disable


        add_to_known_group systemd-journal
        add_to_known_group systemd-network
        add_to_known_group systemd-resolve
    fi

    if dpkg -s geoclue-2.0 &> /dev/null; then
        check_user_shell geoclue disable
        
        add_to_known_group geoclue
    fi

    if dpkg -s kerneloops &> /dev/null; then
        check_user_shell kernoops disable
        
        add_to_known_group kernoops
    fi

    if dpkg -s lightdm &> /dev/null; then
        check_user_shell lightdm disable


        add_to_known_group lightdm
        add_to_known_group nopasswdlogin
    fi

    if dpkg -s whoopsie &> /dev/null; then
        check_user_shell whoopsie disable


        add_to_known_group whoopsie
    fi

    if dpkg -s dbus &> /dev/null; then
        check_user_shell messagebus disable


        add_to_known_group messagebus
    fi

    if dpkg -s usbmuxd &> /dev/null; then
        check_user_shell usbmux disable

    fi

    if dpkg -s speech-dispatcher &> /dev/null; then
        check_user_shell speech-dispatcher disable

    fi

    if dpkg -s rtkit &> /dev/null; then
        check_user_shell rtkit disable

        add_to_known_group rtkit
    fi

    if dpkg -s pulseaudio &> /dev/null; then
        check_user_shell pulse disable


        add_to_known_group pulse
        add_to_known_group pulse-access
    fi

    if dpkg -s kerneloops-daemon &> /dev/null; then
        check_user_shell kernoops disable

    fi

    if dpkg -s hplip &> /dev/null; then
        check_user_shell hplip disable

    fi

    if dpkg -s vsftpd &> /dev/null; then
        check_user_shell ftp disable
        add_to_known_group ftp
    fi

    if dpkg -s dnsmasq-base &> /dev/null; then
        check_user_shell dnsmasq disable

    fi

    if dpkg -s colord &> /dev/null; then
        check_user_shell colord disable


        add_to_known_group colord
    fi

    if dpkg -s avahi-daemon &> /dev/null; then
        check_user_shell avahi disable


        add_to_known_group avahi
        add_to_known_group netdev
    fi

    if dpkg -s avahi-autoipd &> /dev/null; then
        check_user_shell avahi-autoipd disable


        add_to_known_group avahi-autoipd
    fi

    if dpkg -s postfix &> /dev/null; then
        check_user_shell postfix disable


        add_to_known_group postfix
        add_to_known_group postdrop
    fi

    if dpkg -s postgresql &> /dev/null; then
        check_user_shell postgres disable


        add_to_known_group postgres
    fi

    if dpkg -s gdm3 &> /dev/null; then
        check_user_shell gdm disable

        add_to_known_group gdm
    fi

    if dpkg -s openssh-server &> /dev/null; then
        check_user_shell sshd disable

    fi

    if dpkg -s mysql-server &> /dev/null; then
        check_user_shell mysql disable

        add_to_known_group mysql
    fi

    if dpkg -s uuid-runtime &> /dev/null; then
        add_to_known_group uuidd
    fi

    if dpkg -s sane-utils &> /dev/null; then
        add_to_known_group saned
        add_to_known_group scanner
    fi

    if dpkg -s ntp &> /dev/null; then
        add_to_known_group ntp
    fi

    if dpkg -s ssl-cert &> /dev/null; then
        add_to_known_group ssl-cert
    fi

    if dpkg -s libutempter0 &> /dev/null; then
        add_to_known_group utempter
    fi

    if dpkg -s openssh-client &> /dev/null; then
        add_to_known_group ssh
    fi

    if dpkg -s samba &> /dev/null; then
        add_to_known_group sambashare
    fi

    if dpkg -s ifupdown &> /dev/null; then
        add_to_known_group netdev
    fi

    if dpkg -s wpasupplicant &> /dev/null; then
        add_to_known_group netdev
    fi

    if dpkg -s mlocate &> /dev/null; then
        add_to_known_group mlocate
    fi

    if dpkg -s fuse &> /dev/null; then
        add_to_known_group fuse
    fi

    if dpkg -s cron &> /dev/null; then
        add_to_known_group crontab
    fi

    if dpkg -s bluez &> /dev/null; then
        add_to_known_group bluetooth
    fi

    if dpkg -s cups-client &> /dev/null; then
        add_to_known_group lpadmin
    fi

    if dpkg -s cups-pk-helper &> /dev/null; then
        check_user_shell cups-pk-helper disable

        add_to_known_group lpadmin
    fi

    if dpkg -s udev &> /dev/null; then
        add_to_known_group input
    fi

    if dpkg -s dovecot-core &> /dev/null; then
        check_user_shell dovenull disable
        check_user_shell dovecot disable

        add_to_known_group dovenull
        add_to_known_group dovecot
    fi

    if dpkg -s bind9 &> /dev/null; then
        check_user_shell bind disable

        add_to_known_group bind
    fi

    if dpkg -s rsyslog &> /dev/null; then
        check_user_shell syslog disable

        add_to_known_group syslog
    fi

    if dpkg -s mongodb-org-server &> /dev/null; then
        check_user_shell mongodb disable

        add_to_known_group mongodb
    fi

    for i in "${list_of_known_users[@]}"
    do
        find_replace_insert output/active_users.txt $i " known"
    done
}

sort_active_users_txt ()
{
    sudo sort -k 3 -r output/active_users.txt -o output/active_users.txt
}

sort_active_groups_txt ()
{
    sudo sort -k 3 -r output/active_groups.txt -o output/active_groups.txt
}

check_user_shell ()
{
    list_of_known_users+=($1)
    user_shell=( $(grep "^$1:" /etc/passwd | cut -d : -f 7) )

    if [[ "$2" == "disable" ]]; then
        if [[ "$user_shell" != "/bin/false" && "$user_shell" != "/usr/sbin/nologin" ]]; then
            echo "# user_with_bad_shell : $1 expect /bin/false or /usr/sbin/nologin but got $user_shell" | tee -a output/check_user_error.txt
            echo "sudo sh -c 'chsh -s /bin/false $1'" | tee -a output/check_user_error.txt
        fi
        check_password $1 lock
    else
        if [[ "$2" != "$user_shell" ]]; then
            echo "# user_with_bad_shell : $1 expect $2 but got $user_shell" | tee -a output/check_user_error.txt
            echo "sudo sh -c 'chsh -s $2 $1'" | tee -a output/check_user_error.txt
        fi

    fi
}

add_to_known_group()
{
    list_of_known_group+=($1)
    find_replace_insert output/active_groups.txt $1 " known"
}

check_password()
{
    # check_password <user name> absent : expect user do not have a line in /etc/shadow
    # check_password <user name> lock : expect user have either "*" or "!" in password hash field

    shadow_line=$(grep $1 /etc/shadow)
    echo /etc/shadow has line for $1 $shadow_line
    #status=( $(passwd --status $1 | cut -d " " -f 2) )
    shadow_hash=$(echo $shadow_line | cut -d : -f2)

    if [[ "$2" == "absent" && "$shadow_line" != "" ]]; then
        echo "# user_with_bad_password : $1 should not have a line in /etc/shadow but got $shadow_line, remove this line" | tee -a output/check_user_error.txt
        echo "" | tee -a output/check_user_error.txt
    elif [[ "$2" == "lock" ]]; then
        if [[ $shadow_line == "" ]]; then
            echo "# user_with_bad_password : $1 expect have a line in /etc/shadow" | tee -a output/check_user_error.txt
            #echo "sudo sh -c 'passwd $1'" | tee -a output/check_user_error.txt
        elif echo $shadow_line | grep -e "*" ; then
            :
        elif echo $shadow_line | grep -e "!" ; then
            :
        else 
            echo "# user_with_bad_password : $1 expect have * or ! in password hash field" | tee -a outputu/check_user_error.txt
            echo "sudo sh -c 'passwd -dl $1'" | tee -a outputu/check_user_error.txt
        fi
    elif "$2" == ""; then
        if [[ $shadow_line == "" ]]; then
            echo "# user_with_bad_password : $1 does not have a password" | tee -a output/check_user_error.txt
            #echo "sudo sh -c 'passwd $1'" | tee -a output/check_user_error.txt
        elif echo $shadow_line | cut -d : -f 2 | grep "*"; then
            echo "# user_with_bad_password : $1 does not have a password" | tee -a output/check_user_error.txt
            #echo "sudo sh -c 'passwd $1'" | tee -a output/check_user_error.txt
        elif echo $shadow_line | cut -d : -f 2 | grep "!"; then
            echo "# user_with_bad_password : $1 does not have a password" | tee -a output/check_user_error.txt
            #echo "sudo shd -c 'passwd $1'" | tee -a output/check_user_error.txt
        fi
    fi
}

check_user_password_status()
{
    user=$1
    shadow_line=$(grep ^$user: /etc/shadow)

    # check if user has a line in /etc/shadow
    if [[ $shadow_line == "" ]]; then
        echo "# check_user_password_status : $user does not have a password" | tee -a output/check_user_error.txt
        #echo "sudo sh -c 'passwd $user'" | tee -a output/check_user_error.txt
    else
        pass_status=$(echo $shadow_line | cut -d :  -f 2)
        pass_min_day=$(echo $shadow_line | cut -d : -f 4)
        pass_max_day=$(echo $shadow_line | cut -d : -f 5)
        pass_warn_age=$(echo $shadow_line | cut -d : -f 6)
        inactive=$(echo $shadow_line | cut -d : -f 7)

        # check if user is password protected
        if echo $pass_status | grep "*"; then
            echo "# check_user_password_status : $user does not have a password" | tee -a output/check_user_error.txt
            #echo "sudo sh -c 'passwd $user'" | tee -a output/check_user_error.txt
        elif echo $pass_status | grep "!"; then
            echo "# check_user_password_status : $user does not have a password" | tee -a output/check_user_error.txt
            #echo "sudo sh -c 'passwd $user'" | tee -a output/check_user_error.txt
        fi

        # check pass_min_day
        if [ -z "$pass_min_day" ]; then
            echo "# check_user_password_status : $user pass_min_day is less than 14" | tee -a output/check_user_error.txt
            echo "sudo sh -c 'chage -m 14 $user'" | tee -a output/check_user_error.txt
        elif [[ $pass_min_day -lt 14 ]]; then
            echo "# check_user_password_status : $user pass_min_day is less than 14" | tee -a output/check_user_error.txt
            echo "sudo sh -c 'chage -m 14 $user'" | tee -a output/check_user_error.txt
        fi

        # check pass_max_day
        if [ -z "$pass_max_day" ]; then
            echo "# check_user_password_status : $user pass_max_day is greater than 90" | tee -a output/check_user_error.txt
            echo "sudo sh -c 'chage -M 90 $user'" | tee -a output/check_user_error.txt
        elif [[ $pass_max_day -gt 90 ]]; then
            echo "# check_user_password_status : $user pass_max_day is greater than 90" | tee -a output/check_user_error.txt
            echo "sudo sh -c 'chage -M 90 $user'" | tee -a output/check_user_error.txt
        fi

        # check pass_warn_age
        if [ -z "$pass_warn_age" ]; then
            echo "# check_user_password_status : $user pass_warn_age is greater than 7" | tee -a output/check_user_error.txt
            echo "sudo sh -c 'chage -W 7 $user'" | tee -a output/check_user_error.txt
        elif [[ $pass_warn_age -gt 7 ]]; then
            echo "# check_user_password_status : $user pass_warn_age is greater than 7" | tee -a output/check_user_error.txt
            echo "sudo sh -c 'chage -W 7 $user'" | tee -a output/check_user_error.txt
        fi
                
        # check inactive
        if [ -z "$inactive" ]; then
            echo "# check_user_password_status : $user inactive is greater than 30" | tee -a output/check_user_error.txt
            echo "sudo sh -c 'chage -I 30 $user'" | tee -a output/check_user_error.txt
        elif [[ $inactive -gt 30 ]]; then
            echo "# check_user_password_status : $user inactive is greater than 30" | tee -a output/check_user_error.txt
            echo "sudo sh -c 'chage -I 30 $user'" | tee -a output/check_user_error.txt
        fi
                
    fi
}

rl_ubuntu_1604_0035()
{
    # ensure all groups in /etc/passwd exist in /etc/group
    for i in $(cut -s -d: -f4 /etc/passwd | sort -u); do
        grep -q -P "^.*?:[^:]*:$i:" /etc/group
        if [ $? -ne 0 ]; then
            echo "Group $i is refereced by /etc/passwd but does not exist in /etc/group: sudo groupadd [new groupname] -g $i"
        fi
    done
}

# ensure no duplicate UIDs exist
rl_ubuntu_1604_0036()
{
#    cat /etc/passwd | cut -d : -f 3 | sort -n | uniq -c | while read x; do 
#        [ -z "${x}" ] && break
#        set - $x
#        if [ $1 -gt 1 ]; then
#            users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
#            echo "Duplicate UID ($2) : ${users}"
#        fi
#    done

    duplicate_uid_list=( $(cut -s -d : -f 3 /etc/passwd | sort -n | uniq -d) )
    echo ${duplicate_uid_list[*]}

    duplicate_user_uid_list=()
    for duplicate_uid in ${duplicate_uid_list[@]}; do
        duplicate_user_uid_list+=( $( grep [^:]*:[^:]*:$duplicate_uid:[^:]*:[^:]*:[^:]*:[^:]* /etc/passwd | cut -d : -f 1,3 ) )
    done
    echo ${duplicate_user_uid_list[*]}

    new_uid=1000
    for duplicate_user_uid in ${duplicate_user_uid_list[@]}; do

        duplicate_user=$(echo $duplicate_user_uid | cut -d : -f 1)
        duplicate_uid=$(echo $duplicate_user_uid | cut -d : -f 2)

        if [ $duplicate_user !=  "root" ]; then
            while [ $new_uid -lt 65536 ]; do
                new_uid=$[$new_uid+1]
                cut -s -d : -f 3 /etc/passwd | grep $new_uid || break
            done
            echo "# rl_ubuntu_1604_0036 : duplicate uid $duplicate_uid in /etc/passwd" | tee -a output/check_user_error.txt
            echo "sudo sh -c 'usermod -u $new_uid $duplicate_user'" | tee -a output/check_user_error.txt
        fi
    done
}

# ensure no duplicate GIDs exits
rl_ubuntu_1604_0037()
{
#    cat /etc/group | cut -s -d : -f 3 | sort -n | uniq -c | while read x; do
#        [ -z "${x}" ] && break
#        set - $x
#        if [ $1 -gt 1 ]; then
#            groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
#            echo "Duplicate GID ($2): ${groups}"
#        fi
#    done

    duplicate_gid_list=( $(cut -s -d : -f 3 /etc/group | sort -n | uniq -d) )
    echo ${duplicate_gid_list[*]}

    duplicate_group_gid_list=()
    for duplicate_gid in ${duplicate_gid_list[@]}; do
        duplicate_group_gid_list+=( $( grep [^:]*:[^:]*:$duplicate_gid:[^:]* /etc/group | cut -d : -f 1,3 ) )
    done
    echo ${duplicate_group_gid_list[*]}

    new_gid=1000
    for duplicate_group_gid in ${duplicate_group_gid_list[@]}; do

        duplicate_group=$(echo $duplicate_group_gid | cut -d : -f 1)
        duplicate_gid=$(echo $duplicate_group_gid | cut -d : -f 2)
        while [ $new_gid -lt 65536 ]; do
            new_gid=$[$new_gid+1]
            cut -s -d : -f 3 /etc/group | grep $new_gid || break
        done
        echo "# rl_ubuntu_1604_0036 : duplicate gid $duplicate_gid in /etc/group" | tee -a output/check_user_error.txt
        echo "sudo sh -c 'groupmod -g $new_gid $duplicate_group'" | tee -a output/check_user_error.txt
    done
}

rl_ubuntu_1604_0022 ()
{
    bad_line_list=( $(grep -v "[^:]*:x:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*" /etc/passwd) )

    for bad_line in ${bad_line_list[@]};
    do
        echo bad
        echo "# rl_ubuntu_1604_0022 : /etc/passwd has bad hash in $bad_line" | tee -a output/check_user_error.txt
        echo "" | tee -a output/check_user_error.txt
    done
}

rl_ubuntu_1604_0024 ()
{
    fake_root_list=($(grep "[^:]*:[^:]*:0:[^:]*:[^:]*:[^:]*:[^:]*" /etc/passwd |grep -v "^root:[^:]*:0:0:") )
    fake_root_list+=($(grep "[^:]*:[^:]*:[^:]*:0:[^:]*:[^:]*:[^:]*" /etc/passwd | grep -v "^root:[^:]*:0:0:") )

    for fake_root in ${fake_root_list[@]};
    do
        echo "# rl_ubuntu_1604_0024 : modify uid/giu of $fake_root to non-zero value" | tee -a output/check_user_error.txt
        echo "" | tee -a output/check_user_error.txt
    done
}

rl_ubuntu_1604_0029 ()
{
    # Encure no legacy "+" entries exists in /etc/passwd
    bad_line_list=( $( grep "^+:" /etc/passwd ) )
    
    for bad_line in ${bad_line_list[@]};
    do
        echo "# rl_ubuntu_1604_0029 : 'Legacy + entries exists in /etc/passwd : remove $bad_line from /etc/passwd'" | tee -a output/check_user_error.txt
        echo "" | tee -a output/check_user_error.txt
    done
}

rl_ubuntu_1604_0035 ()
{
       # Ensure all groups in /etc/passwd exist in /etc/group
    for i in $(cut -s -d : -f4 /etc/passwd | sort -u );
    do
        grep -q -P "^.*?:[^:]*:$i:" /etc/group

        if [ $? -ne 0 ];
        then
            new_group="group_$RANDOM"
            grep -q "^$new_group:" /etc/group
            while [ $? -eq 0 ]
            do
                new_group="group_$RANDOM"
                grep -q "^$new_group:" /etc/group
            done
            echo "# rl_ubuntu_1604_0035 : 'Group $i is referenced by /etc/passwd but does not exist in /etc/group'" | tee -a output/check_user_error.txt
            echo "sudo sh -c 'groupadd $new_group -g $i'" | tee -a output/check_user_error.txt
        fi
    done
}

rl_ubuntu_1604_0124 ()
{
    #Ensure no duplicate user names exist
    cat /etc/passwd | cut -f 1 -d : | sort -n | uniq -c | while read x; do
        [ -z "${x}" ] && break
        set - $x
        if [ $1 -gt 1 ]; then
            uids=`awk -F: '($1 == n) {print $3}' n=$2 /etc/passwd | xargs`
            echo "# rl_ubuntu_1604_0124 : 'Duplicate User Name ($2): ${uids} : remove duplicates in /etc/passwd'" | tee -a output/check_user_error.txt
            echo "" | tee -a output/check_user_error.txt
        fi
    done
}

rl_ubuntu_1604_0038 ()
{
    # Ensure no duplicate group names exist
    cat /etc/group | cut -f 1 -d : | sort -n |uniq -c | while read x ; do
        [ -z "${x}" ] && break
        set - $x
        if [ $1 -gt 1 ]; then
            gids =`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs `
            echo "# rl_ubuntu_1604_0038 : 'Duplicate Group Name ($2) : ${gids}'" | tee -a output/check_user_error.txt
            echo "" | tee -a output/check_user_error.txt
        fi
    done
}

rl_ubuntu_1604_0039 ()
{
    # Ensure shadow group is empty
    if grep ^shadow:[^:]*:[^:]*:[^:] /etc/group; then
        shadow_line=$(grep ^shadow: /etc/group)
        new_shadow_line=$(echo $shadow_line | cut -d : -f 1-3)
        echo "# rl_ubuntu_1604_0039 : 'shadow group is not empty : replace \"$shadow_line\" with \"$new_shadow_line:\ in /etc/group'" | tee -a output/check_user_error.txt
        echo "" | tee -a output/check_user_error.txt
    fi

    shadow_gid=$(grep ^shadow: /etc/group | cut -d : -f 3)
    
    user_gid_list=( $(cut -d : -f 1,4 /etc/passwd) )

    for user_gid in ${user_gid_list[@]};
    do
        user=$(echo $user_gid | cut -d : -f 1)
        gid=$(echo $user_gid | cut -d : -f 2)
        shadow_line=$(grep $user:[^:]*:[^:]*:$gid: /etc/passwd)
        if [ $gid == $shadow_gid ]; then
            echo "# rl_ubuntu_1604_0039 : 'shadow group is not empty : fix or remove \"$shadow_line\" in /etc/passwd'" | tee -a output/check_user_error.txt
            echo "" | tee -a output/check_user_error.txt
        fi
    done
}

get_list_of_unknown_users ()
{
    list_of_unknown_users=()
    while IFS= read line; do
        unknown_user=$( echo $line | grep -e "-----------> unknown" | cut -d " " -f 1)
        if [ ! -z "$unknown_user" ]; then
            list_of_unknown_users+=($unknown_user)
        fi
    done < "output/active_users.txt"
}

print_unknown_users ()
{
    for unknown_user in ${list_of_unknown_users[@]}
    do
        echo "unknown user : $unknown_user"
    done
}

remove_unknown_users_not_in_list_of_authorized_users ()
{
    for unknown_user in ${list_of_unknown_users[@]}
    do
        for authorized_user in ${list_of_authorized_users[@]}
        do
            if [ "$unknown_user" == "$authorized_user" ]; then
                continue 2
            fi
        done
        
        echo "# remove unauthorized user" | tee -a output/check_user_error.txt
        echo "sudo sh -c 'userdel -r $unknown_user'" | tee -a output/check_user_error.txt
    done
}

get_list_of_unknown_groups ()
{
    list_of_unknown_groups=()
    while IFS= read line; do
        unknown_group=$( echo $line | grep -e "-----------> unknown" | cut -d " " -f 1)
        if [ ! -z "$unknown_group" ]; then
            list_of_unknown_groups+=($unknown_group)
        fi
    done < "output/active_groups.txt"
}

print_unknown_groups ()
{
    for unknown_group in ${list_of_unknown_groups[@]}
    do
        echo "unknown group : $unknown_group"
    done
}

remove_unknown_groups_not_in_list_of_authorized_groups ()
{
    for unknown_group in ${list_of_unknown_groups[@]}
    do
        for authorized_group in ${list_of_authorized_groups[@]}
        do
            if [ "$unknown_group" == "$authorized_group" ]; then
                continue 2
            fi
        done
        
        echo "# remove unauthorized group" | tee -a output/check_user_error.txt
        echo "sudo sh -c 'groupdel $unknown_group'" | tee -a output/check_user_error.txt
    done
}

add_groups_in_list_of_authorized_groups ()
{
    for group in ${list_of_authorized_groups[@]}
    do
        find_replace_insert output/active_groups.txt $group " -----------> authorized"
        if ! getent group $group ; then
            echo "# users.txt : add authorized group not exists" | tee -a output/check_user_error.txt
            echo "sudo sh -c 'groupadd -f $group'" | tee -a output/check_user_error.txt
        fi
    done

}

parse_users_txt ()
{
    list_of_authorized_user_password_group=()
    list_of_authorized_users=()
    list_of_authorized_groups=()

    while IFS= read line; do
        echo $line
        list_of_authorized_user_password_group+=("${line}")

        myarray=($line)
        username=${myarray[0]}
        password=${myarray[1]}
        # echo $username has password $password

        user_groups=("${myarray[@]:2}")
        user_groups+=($username)

        # record authorized user and group
        list_of_authorized_users+=($username)

        for i in ${user_groups[@]}
        do
            list_of_authorized_groups+=($i)
        done
    done < "users.txt"
}

setup_user_from_users_txt ()
{
    for ((i = 0; i < ${#list_of_authorized_user_password_group[@]}; i++))
    do
        line=${list_of_authorized_user_password_group[$i]}
        echo $line
        myarray=($line)
        username=${myarray[0]}
        password=${myarray[1]}
        echo $username has password $password

        user_groups=("${myarray[@]:2}")
        user_groups+=($username)

        if id "$username" > /dev/null;  then
            # authorize user 
            check_user_shell $username /bin/bash

            # make user authorized in active_users.txt
            find_replace_insert output/active_users.txt $username " -----------> authorized"

            # mark group authrozed in active_groups.txt
            find_replace_insert output/active_groups.txt $username " -----------> authorized"

            # change password
            password_shadow=$(getent shadow $username | cut -d : -f 2)
            password_algorithm=$(echo $password_shadow | cut -d $ -f 2)
            password_salt=$(echo $password_shadow | cut -d $ -f 3)
            password_hash=$(echo $password_shadow | cut -d $ -f 4)
            my_hash=$(mkpasswd --method=sha-512 --salt=$password_salt $password) 
            
             # echo $password_algorithm | tee -a output/check_user_error.txt
             # echo $password_salt | tee -a output/check_user_error.txt
             # echo $password_hash | tee -a output/check_user_error.txt
             # echo $password_shadow | tee -a output/check_user_error.txt
             # echo $my_hash | tee -a output/check_user_error.txt
             
             if [ "$password_shadow" != "$my_hash" ]; then
                 echo "# users.txt : change_user_password" | tee -a output/check_user_error.txt
                 echo "sudo sh -c 'echo $username:$password | chpasswd'" | tee -a output/check_user_error.txt
             fi
 
            # get user current group
            user_current_groups=$(id -nG $username)

             # add user to authorized group
             for authorize_group in ${user_groups[@]};
             do
                 for group in ${user_current_groups[@]};
                 do
                     if [ "$group" == "$authorize_group" ]; then
                         continue 2
                     fi
                 done
                 echo "# users.txt :  should have group $authorize_group" | tee -a output/check_user_error.txt
                 echo "sudo sh -c 'gpasswd -a $username $authorize_group'" | tee -a output/check_user_error.txt
             done
            
            # remove user from unauthorized group
            for group in ${user_current_groups[@]};
            do
                for authorize_group in ${user_groups[@]};
                do
                    if [ "$group" == "$authorize_group" ]; then
                        continue 2
                    fi
                done
                echo "# users.txt : $username should not have group $group" | tee -a output/check_user_error.txt
                echo "sudo sh -c 'gpasswd -d $username $group'" | tee -a output/check_user_error.txt
            done

             # check_user_password_status
             echo check_user_password_status $username
             check_user_password_status $username
         else
             # add user
             echo not found $username
             echo "# users.txt : $username not found" | tee -a output/check_user_error.txt
             echo "sudo sh -c 'useradd -m $username -g $username -s /bin/bash'" | tee -a output/check_user_error.txt
             echo "sudo sh -c 'echo $username:$password | chpasswd'" | tee -a output/check_user_error.txt
         
             # add user to authorized group
             for authorize_group in ${user_groups[@]};
             do
                 echo "# users.txt :  should have group $authorize_group" | tee -a output/check_user_error.txt
                 echo "sudo sh -c 'gpasswd -a $username $authorize_group'" | tee -a output/check_user_error.txt
             done

            # harden user setting
            echo "sudo sh -c 'chage -m 14 $username'" | tee -a output/check_user_error.txt
            echo "sudo sh -c 'chage -M 90 $username'" | tee -a output/check_user_error.txt
            echo "sudo sh -c 'chage -W 7 $username'" | tee -a output/check_user_error.txt
            echo "sudo sh -c 'chage -I 30 $username'" | tee -a output/check_user_error.txt
            
        fi
    done

}

print_users_txt()
{
    for ((i = 0; i < ${#list_of_authorized_user_password_group[@]}; i++))
    do
            echo "users.txt : ${list_of_authorized_user_password_group[$i]}"
    done

     for user in ${list_of_authorized_users[@]}
     do
         echo "authorized user : $user"
     done
 
     for group in ${list_of_authorized_groups[@]}
     do    
         echo "authorized group : $group"
     done
}

init
get_active_users_and_groups
filter_users_and_groups_from_package
parse_users_txt
get_list_of_unknown_users
remove_unknown_users_not_in_list_of_authorized_users
get_list_of_unknown_groups
remove_unknown_groups_not_in_list_of_authorized_groups
add_groups_in_list_of_authorized_groups
setup_user_from_users_txt
rl_ubuntu_1604_0022
rl_ubuntu_1604_0024
rl_ubuntu_1604_0029
rl_ubuntu_1604_0035
rl_ubuntu_1604_0036
rl_ubuntu_1604_0037
rl_ubuntu_1604_0124
rl_ubuntu_1604_0038
rl_ubuntu_1604_0039
sort_active_users_txt
sort_active_groups_txt
