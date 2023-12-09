#!/bin/bash

if [ $# -lt 2 ]
then
	echo "No arguments provided"
	exit 1
fi

parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

topology=$1
output_folder=$2

n_redirected_packets=$3
time_threshold=$4
count_min_size=$5

ruleset_folder=$6


if [ ! -d $output_folder ]
then
	echo "Folder "$output_folder" does not exist"
	exit 1
fi

if [ -z $ruleset_folder ]
then
	ruleset_folder="../snort/rules/snort3-registered"
fi

if [ -z $n_redirected_packets ]
then
	n_redirected_packets=10
fi

if [ -z $time_threshold ]
then
	time_threshold=10
fi

if [ -z $count_min_size ]
then
	count_min_size=1024
fi

# Update topology in Makefile
sed -i -e 's|TOPO = topologies/[^/"]*|TOPO = topologies/'$topology'|' ../src/Makefile

# Update data plane parameters
sed -i -e 's|MAX_PACKETS=[^;"]*|MAX_PACKETS='$n_redirected_packets'|' ../src/include/header.p4
sed -i -e 's|TIME_THRESHOLD=[^;"]*|TIME_THRESHOLD='$time_threshold'|' ../src/include/header.p4
sed -i -e 's|COUNT_MIN_SIZE=[^;"]*|COUNT_MIN_SIZE='$count_min_size'|' ../src/include/header.p4

config_file="$parent_path""/experiment_configuration/""$topology"".json"

# Update rule path in configuration file
sed -i -e 's|--rule-path [^ "]*|--rule-path '$ruleset_folder'|' $config_file

# Create snort log folders
mkdir ../snort/logs
mkdir ../snort/logs/eth0
mkdir ../snort/logs/hsnort-eth1
mkdir ../snort/logs/hsnort-eth2
mkdir ../snort/logs/hsnort-eth3

# Emulate with each PCAP in the CIC-IDS 2017 dataset
for pcap in ../../CICIDS2017-PCAPS/*; do
	pcap_name=$(echo $pcap | sed "s/.*\///")
	sed -i -e 's|CICIDS2017-PCAPS\/[^\"]*|CICIDS2017-PCAPS/'$pcap_name'|' $config_file

	cd ../src
	make clean
	make TEST_JSON=$config_file > $output_folder"output.txt"

	IFS='-' read -r -a array <<< "$pcap_name"

	mkdir $output_folder${array[0]}
	mv $output_folder"output.txt" $output_folder${array[0]}

	sudo chmod -R a+rwx ../snort/logs/*
	cp -r ../snort/logs/* $output_folder/"${array[0]}"

	rm ../snort/logs/eth0/*
	rm ../snort/logs/hsnort-eth1/*
	rm ../snort/logs/hsnort-eth2/*
	rm ../snort/logs/hsnort-eth3/*

	cd ../testing
done;

cd ../src
make clean

stty erase ^H
