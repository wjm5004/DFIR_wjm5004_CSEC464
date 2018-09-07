#!/bin/bash

# Usage: lab1.sh [-c] [-r/--remote <IP> -u/--user <USER>] [-e/--email <EMAIL>]
# Grabs forensic information from a system
# Specify a remote ip and username to run non-locally
# -c will output results to output.csv
# specifying an email will send the csv output to the destination

script=$(realpath $0)
csv_output=""
exec 2> /dev/null
header=$'------------------------------------------\n'

time_write () {
	local output=$header
	output+=$'time, timezone, up since\n'
	curr_time=$(date | tr -s " " | cut -d " " -f4)
	timezone=$(date +"%Z %z")
	uptime_since=$(uptime -s)
	output+="$curr_time, $timezone, $uptime_since"
	output+=$'\n'
	output+=$header
	echo "$output"

	csv_output+=$'time, timezone, up since\n'
	csv_output+=$curr_time,$timezone,$uptime_since$'\n'
}

version_info () {
	local output=$header
	output+=$'OS version, Name, Kernel Version\n'
	major_minor=$(lsb_release -a -s | cut -d$'\n' -f3)
	typical_name=$(lsb_release -a -s | cut -d$'\n' -f1)
	kernel_version=$(uname --kernel-version)
	output+="$major_minor, $typical_name, $kernel_version"
	output+=$'\n'
	output+=$header
	echo "$output"

	csv_output+=$'\nOS version, name, kernel_version\n'
	csv_output+=$major_minor,$typical_name,$kernel_version$'\n'
}

hardware_info () {
	local output=$header
	output+=$'CPU, RAM\n'
	cpu_info=$(lscpu | cut -d$'\n' -f13 | cut -d " " -f12-)
	mem_total=$(free|awk '/^Mem:/{print $2}')
	output+="$cpu_info, $mem_total"
	output+=$'\n'
	output+=$header

	csv_output+=$'\nCPU, RAM\n'
	csv_output+="$cpu_info, $mem_total"$'\n'
	csv_output+=$'\nFilesystem,Size\n'

	output+=$'Filesystem, Size\n'
	hdd=$(df -BM | cut -d$'\n' -f2- | tr -s " " | cut -d " " -f1)
	hdd_array=( $hdd )	
	size=$(df -BM | cut -d$'\n' -f2- | tr -s " " | cut -d " " -f2)
	size_array=( $size )
	for x in "${!hdd_array[@]}"; do
		output+="${hdd_array[x]}, ${size_array[x]}"
		output+=$'\n'

		csv_output+="${hdd_array[x]}, ${size_array[x]}"$'\n'
	done
	output+=$header
	output+=$'\n'
	echo "$output"
}

host_info () {
	local output=$header
	output+=$'Hostname, Domainname\n'
	host_name=$(hostname)
	domain_name=$(domainname)
	output+="$host_name, $domain_name"
	output+=$'\n'
	output+=$header
	echo "$output"

	csv_output+=$'\nhostname, domainname\n'
	csv_output+="$host_name, $domain_name"$'\n'
}

user_info () {
	_l="/etc/login.defs"
	_p="/etc/passwd"
	## get mini UID limit ##
	l=$(grep "^UID_MIN" $_l)
	## get max UID limit ##
	l1=$(grep "^UID_MAX" $_l)
	local output=$header
	local_users=$(awk -F':' -v "min=${l##UID_MIN}" -v "max=${l1##UID_MAX}" '{ if ( $3 >= min && $3 <= max  && $7 != "/sbin/nologin" ) print $1 }' "$_p")
	system_users=$(awk -F':' -v "min=${l##UID_MIN}" -v "max=${l1##UID_MAX}" '{ if ( !($3 >= min && $3 <= max  && $7 != "/sbin/nologin")) print $1 }' "$_p")
	output+=$'Local Users, Last Login\n'
	csv_output+=$'\nlocal_users, last_login\n'
	for x in "${!local_users[@]}"; do
		last_login=$(last ${local_users[x]} | cut -d$'\n' -f1 | tr -s " " | cut -d " " -f4-7)
		output+="${local_users[x]}, $last_login"
		output+=$'\n'
		csv_output+="${local_users[x]}, $last_login"$'\n'
	done
	output+=$'\n'
	output+=$'System Uses\n'
	csv_output+=$'\nsystem_users\n'

	for x in "${!system_users[@]}"; do
		output+="${system_users[x]}"
		output+=$'\n'
		csv_output+="${system_users[x]}"$'\n'
	done
	output+=$header
	output+=$'\n'
	echo "$output"
}

run_at_boot () {
	local output=$header
	boot_programs=$(ls /etc/init.d)
	output+=$'Program name\n'
	output+=$boot_programs
	output+=$'\n'
	output+=$header
	echo "$output"

	csv_output+=$'\nboot_programs\n'
	csv_output+="$boot_programs"$'\n'
}

scheduled_tasks () {
	local output=$header
	crontabs=()
	csv_output+=$'\nuser,cron\n'
	for user in $(cut -f1 -d: /etc/passwd); do
		user_cron=$(sudo crontab -u $user -l | sed '/^#/ d');
		if ! [ -z "$user_cron" ]
		then
			crontabs+=$user
			crontabs+=$'\n'
			crontabs+=$user_cron
			csv_output+="$user,$user_cron"$'\n'
		fi
	done
	output+=$crontabs
	output+=$'\n'
	output+=$header
	echo "$output"
}

network () {
	local output=$header
	arp_table=$(arp -e)
	output+=$'Arp table\n'
	output+=$arp_table
	output+=$'\n'
	csv_output+=$'arp_table\n'
	csv_output+=$arp_table
	csv_output+=$'\n'
	output+=$'Interfaces\n'
	csv_output+=$'\ninterface, address\n'
	for interface in $(ls /sys/class/net/); do
		if ! [ -z "$(cat /sys/class/net/$interface/address)" ]
		then
			addr=$(cat /sys/class/net/$interface/address)
			output+="$interface, $addr"
			output+=$'\n'
			csv_output+="$interface, $addr"$'\n'
		fi
	done
	output+=$'Routing Table\n'
	output+=$(ip route)
	csv_output+=$'\nrouting_table\n'
	csv_output+=$(ip route)$'\n'
	output+=$'\n'
	output+=$'Interface, IP address\n'
	csv_output+=$'\ninterface, ip_addr\n'
	for x in $(ifconfig -s | cut -d " " -f1); do 
		res=$(ifconfig $x | grep 'inet ' | tr -s ' ' | cut -d " " -f3);
		if ! [ -z $"$res" ]
		then
			output+="$x, $res"
			output+=$'\n'
			csv_output+="$x, $res"$'\n'
		fi 
	done
	output+=$'DHCP Servers\n'
	csv_output+=$'\ndhcp_servers\n'
	dhcp_servers=$(cat $(ps aux | grep -o '[/]var/lib/NetworkManager/\S*.lease') | grep dhcp-server-identifier | cut -d " " -f5 | tr -s ';')
	output+=$(sed 's/.$//' <<< $dhcp_servers)
	csv_output+=$(sed 's/.$//' <<< $dhcp_servers)$'\n'
	output+=$'\n'
	output+=$'DNS Servers\n'
	output+=$( nmcli dev show | grep DNS | tr -s " " | cut -d " " -f2)
	csv_output+=$'\ndns_servers\n'"$( nmcli dev show | grep DNS | tr -s " " | cut -d " " -f2)"$'\n'
	output+=$'\n'
	output+=$'Interface, gateway\n'
	gateways=($(route | tr -s " " | cut -d$'\n' -f3- | cut -d " " -f2))
	interfaces=($(route | tr -s " " | cut -d$'\n' -f3- | cut -d " " -f8))
	csv_output+=$'\ninterface, gateway\n'
	for index in "${!gateways[@]}"; do
		output+="${interfaces[index]}, ${gateways[index]}"
		output+=$'\n'
		csv_output+="${interfaces[index]}, ${gateways[index]}"$'\n'
	done
	output+=$'Protocol, IP:Port, Process\n'
	csv_output+=$'\nprotocol, ip:port, process\n'
	protocols=($(netstat -tunlp | tr -s " " | cut -d " " -f1))
	ip_port=($(netstat -tunlp | tr -s " " | cut -d " " -f4))
	process=($(netstat -tunlp | cut -d$'\n' -f3- | tr -s " " | rev | cut -d " " -f2 | rev))
	for index in "${!protocols[@]}"; do
		output+="${protocols[index]}, ${ip_port[index]}, ${process[index]}"
		output+=$'\n'
		csv_output+="${protocols[index]}, ${ip_port[index]}, ${process[index]}"$'\n'
	done
	output+=$'Remote IP, Local Port, Remote Port, Protocol, Time, Process\n'
	csv_output+=$'\nremote_ip, remote_port, local_port, protocol, time, process\n'
	#established=($(netstat -tunalp | grep 'ESTABLISHED' | tr -s " "))
	#or conn in $established; do
	while read -r conn; do
		remote_ip=$(echo $conn | cut -d " " -f5 | cut -d: -f1)
		local_port=$(echo $conn | cut -d " " -f4 | cut -d: -f2)
		remote_port=$(echo $conn | cut -d " " -f5 | cut -d: -f2)
		protocol=$(echo $conn | cut -d " " -f1)
		process=$(echo $conn | cut -d " " -f7)
		pid=$(echo $process | cut -d "/" -f1)
		timestamp=$(ps -ef | grep $pid | cut -d$'\n' -f1 | tr -s " " | cut -d " " -f5)
		output+="$remote_ip, $local_port, $remote_port, $protocol, $timestamp, $process"
		csv_output+="$remote_ip, $remote_port, $local_port, $protocol, $timestamp, $process"$'\n'

		output+=$'\n'
	done <<< $(netstat -tunalp | grep 'ESTABLISHED' | tr -s " ")
	echo "$output"
}

software () {
	local output=$header
	output+=$'Installed Packages\n'
	packages=$(apt list --installed | cut -d$'\n' -f2-)
	output+=$packages$'\n'
	output+=$header
	output+=$'\n'
	echo "$output"

	csv_output+=$'\ninstalled_pckgs\n'
	csv_output+="$packages"$'\n'
}

processes () {
	local output=$header
	output+=$'Process name, PID, PPID, Path, Owner\n'
	ps_list=$(ps -ef | cut -d$'\n' -f2- | tr -s " ")
	csv_output+=$'\nprocess_name, pid, ppid, path, pwner\n'
	while read -r proc; do
		pid=$(echo $proc | cut -d " " -f2)
		proc_name=$(ps -p $pid -o comm=)
		ppid=$(echo $proc | cut -d " " -f3)
		path=$(readlink /proc/$pid/exe)
		owner=$(echo $proc | cut -d " " -f1)
		output+="$proc_name, $pid, $ppid, $path, $owner"
		output+=$'\n'
		csv_output+="$proc_name, $pid, $ppid, $path, $owner"$'\n'
	done <<< $ps_list
	echo "$output"
}

drivers () {
	local output=$header
	output+=$'Driver name, file location, version, provider name\n'
	csv_output+=$'\ndriver_name, file_path, version, provider_name\n'
	driver_list=$(lsmod | tr -s " " | cut -d$'\n' -f2- | cut -d " " -f1)
	while read -r drive; do
		driver_name=$drive
		driver_location=$(modinfo $drive -F filename)
		driver_version=$(modinfo $drive -F srcversion)
		driver_provider=$(modinfo $drive -F author)
		output+="$driver_name, $driver_location, $driver_version, $driver_provider"
		output+=$'\n'
		csv_output+="$driver_name, $driver_location, $driver_version, $driver_provider"$'\n'

	done <<< $driver_list
	output+=$header
	echo "$output"
}

files () {
	local output=$header
	for curr_user in $(ls /home); do
		output+=$curr_user
		csv_output+=$'\n'"$curr_user"$'_downloads\n'
		output+=$'\nDownloads\n'
		csv_output+=$(ls /home/$curr_user/Downloads)
		output+=$(ls /home/$curr_user/Downloads)$'\n'
		output+=$'\nDocuments\n'
		csv_output+=$'\n'"$curr_user"$'_documents\n'
		output+=$(ls /home/$curr_user/Documents)
		csv_output+=$(ls /home/$curr_user/Documents)$'\n'
		output+=$'\n'
	done
	output+=$header
	echo "$output"
}

sudo_users () {
	local output=$header
	output+=$'Sudo Users\n'
	csv_output+=$'\nsudo_users\n'
	output+=$(grep -Po '^sudo.+:\K.*$' /etc/group)
	output+=$'\n'
	csv_output+=$(grep -Po '^sudo.+:\K.*$' /etc/group)$'\n'
	output+=$header
	echo "$output"
}

active_users () {
	local output=$header
	output+=$'Logged in Users\n'
	user_line=$(w | cut -d$'\n' -f3- | tr -s " ")
	output+=$'Name, TTY, Shell\n'
	csv_output+=$'\nactive_user, tty, shell\n'
	while read -r curr_user; do
		user_name=$(echo $user_line | cut -d " " -f1)
		tty=$(echo $user_line | cut -d " " -f2)
		shell=$(echo $user_line | cut -d " " -f8)
		output+="$user_name, $tty, $shell"
		output+=$'\n'
		csv_output+="$user_name, $tty, $shell"$'\n'
	done <<< $user_line
	output+=$header
	echo "$output"
}

bash_history () {
	local output=$header
	output+=$'Bash History\n'
	for curr_user in $(ls /home); do
		csv_output+=$'\n'"$curr_user""_bash_history"$'\n'
		output+="$curr_user"
		output+=$'\n'
		bash_history_out=$(cat /home/$curr_user/.bash_history | tail -n 20)
		output+="$bash_history_out"
		output+=$'\n'
		csv_output+="$bash_history_out"$'\n'
	done
	output+=$header
	echo "$output"
}

run () {
	# Required
	time_write
	version_info
	hardware_info
	host_info
	user_info
	run_at_boot
	scheduled_tasks
	network
	software
	processes
	drivers
	files
	# Other 3
	sudo_users
	active_users
	bash_history
}
while [ "$1" != "" ]; do
	case $1 in
		-r | --remote )			shift
								remote=$1
								;;
		-u | --user )			shift
								ssh_user=$1
								;;
		-c | --csv )    		csv=1
								;;
		-e | --email )			shift
								email=$1
								;;
		* )						exit 1
	esac
	shift
done
if [ $remote ]; then
	if ! [ $ssh_user ]; then
		echo "Error: remote option requires a user"
		exit 1
	fi
	$(ssh $ssh_user@$remote 'cat | bash /dev/stdin $csv -s' < $script)
fi
if [ $csv ]; then
 	exec 1> /dev/null
fi
run
if [ $csv ]; then
	echo "$csv_output" >> "output.csv"
	if [ $email ]; then
		cat "output.csv" | mail -s "CSV Output" $email
	fi 
fi
