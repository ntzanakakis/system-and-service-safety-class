#!/bin/bash
# You are NOT allowed to change the files' names!
domainNames="domainNames.txt"
IPAddresses="IPAddresses.txt"
adblockRules="adblockRules"
function adBlock() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-domains"  ]; then
	while read domains; do
		resolve=$(dig $domains +nocomments +noquestion +noauthority +noadditional +nostats +short) #dig just the IP addresses
		ip_arr=($resolve)
		if [[ "${#ip_arr[@]}" -gt '0' ]];then #if there are any IPs
			for (( m=0 ; m < "${#ip_arr[@]}" ; m++))
			do
				if [[ ${ip_arr[m]} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]];then #if the contents are of the form XXX.XXX.XXX.XXX where X is a number
					echo "2- ${ip_arr[m]} has been dropped" #info message
					( echo ${ip_arr[m]} ) >> $IPAddresses #write to IPAddresses file
					iptables -A INPUT -s ${ip_arr[m]} -j DROP #drop packets (block connection)
				elif [[ -z "${ip_arr[m]}" ]];then	#if contents are NULL
					echo "1- Non valid IP found for "${ip_arr[m]}" . Server not responding?"
				else
					echo -e "3- Something else than an IP found for $domains (probably a CNAME), ignoring.."
				fi
			done
		else
			if [[ -z "$resolve" ]];then	
				echo "1- No IP found for $domains . Server not responding?"
			fi
		fi
	done <$domainNames
	# Configure adblock rules based on the domain names of $domainNames file.
        # Write your code here...
        # ...
        # ...
        true
    elif [ "$1" = "-ips"  ]; then
	while read ips; do
		if [[ $ips =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]];then	
			echo "2- $ips has been dropped"
			iptables -A INPUT -s $ips -j DROP
		fi
	done <$IPAddresses
        # Configure adblock rules based on the IP addresses of $IPAddresses file.
        # Write your code here...
        # ...
        # ...
        true
    elif [ "$1" = "-save"  ]; then
        iptables-save > adBlockRules
	# Save rules to $adblockRules file.
        # Write your code here...
        # ...
        # ...
        true
    elif [ "$1" = "-load"  ]; then
        iptables-restore < adBlockRules
	# Load rules from $adblockRules file.
        # Write your code here...
        # ...
        # ...
        true
    elif [ "$1" = "-reset"  ]; then
        iptables -P INPUT ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables -F
	# Reset rules to default settings (i.e. accept all).
        # Write your code here...
        # ...
        # ...
        true
    elif [ "$1" = "-list"  ]; then
        iptables -L
	# List current rules.
        # Write your code here...
        # ...
        # ...
        true
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ips\t\t  Configure adblock rules based on the IP addresses of '$IPAddresses' file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}
adBlock $1
exit