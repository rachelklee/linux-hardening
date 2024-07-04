#!/bin/bash 
setup_user()
{
	echo setup_user
	users=()
	input=$1
	while IFS=' ' read -r -a array
	do
		total=${#array[*]}
		echo $total
		echo "echo \"${array[0]}:${array[1]}\" | chpasswd"
		users+=(${array[0]})

		# get allow group
		for ((i = 2 ; i < $total ; i++));
		do
			echo groups ${array[i]}
			list_of_known_group+=(${array[i]})
		done
	done < "$input"
}

setup_user $1
for names in "${users[@]}"
do
	echo $names
done
