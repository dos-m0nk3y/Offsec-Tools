#!/bin/bash

if [ "$#" -lt 1 ]; then
  printf "Usage: $0 <IP Address> [Parameters]\n"
  exit
fi

interface="$(ip route get $1 | head -n 1 | awk -F 'dev' '{print $2}' | cut -d ' ' -f 2)"
printf "\nInitiating port scan against $1 on $interface"
printf "\nPress any key after the completion of masscan to continue with the nmap scan ...\n\n"

file="PortScan($1)"
masscan -p1-65535,U:1-65535 --rate 500 -e $interface --range "$@" > $file &

while [ true ]; do
  read -t 1 -n 1
  if [ $? = 0 ]; then
    break
  fi
done
pkill masscan

tcp=$(cat $file | grep tcp | awk {'print $4'} | awk -F '/' {'print $1'} | sort -n | tr '\n' ',' | sed 's/,$//')
udp=$(cat $file | grep udp | awk {'print $4'} | awk -F '/' {'print $1'} | sort -n | tr '\n' ',' | sed 's/,$//')

if [ ! -z $tcp ]; then
  printf "\n\nStarting TCP port scan\n\n"
  echo >> $file
  nmap $1 -p $tcp -Pn -sT -sV -sC -oN $file
fi

if [ ! -z $udp ]; then
  printf "\n\nStarting UDP port scan\n\n"
  echo >> $file
  nmap $1 -p $udp -Pn -sU -sV -sC -oN $file --append-output
fi

cat $file | grep -vE "# Nmap|Nmap scan report for|Host is up|Service detection performed" | awk '/./ { e=0 } /^$/ { e += 1 } e <= 1' | sponge $file
