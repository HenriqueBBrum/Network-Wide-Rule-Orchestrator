#!/bin/bash
scriptdir="$(dirname "$0")"
cd $scriptdir

if [ $# -lt 6 ]
then
	echo "Missing arguments"
	exit 1
fi

parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
snort_folder=../../snort/
src_folder=../../src/

output_folder=$1
ruleset_folder=$2
table_entries_file=$3

topology=$4
offloading_algorithm=$5
space_per_sw=$6


if [ ! -d $output_folder ]
then
	echo "Folder "$output_folder" does not exist"
	exit 1
fi

config_file=$parent_path"/experiment_configuration/"$topology".json"

# Update the rule's path in the configuration file
sed -i -e 's|--rule-path [^ ]*|--rule-path '$ruleset_folder'|' $config_file

# Update the table entries file in the configuration file
sed -i -e 's|"table_entries_file": [^,]*|"table_entries_file": "'$table_entries_file'"|' $config_file

# Update the table entries distribution algorithm in the configuration file
sed -i -e 's|"offloading_algorithm": [^,]*|"offloading_algorithm": "'$offloading_algorithm'"|' $config_file

# Update topology in Makefile
sed -i -e 's|TOPO = topologies/[^/]*|TOPO = topologies/'$topology'|' ../src/Makefile

# Update available memory space in sswitches in the "network_info" file
sed -i -e 's|"free_table_entries" : [^,]*|"free_table_entries" : '$space_per_sw'|' "../src/topologies/"$topology"/network_info.json"

echo $ruleset_folder
echo $table_entries_file
echo $topology
echo $offloading_algorithm
echo $space_per_sw

# Specify the data plane parameter
n_redirected_packets=200
time_threshold=10
count_min_size=16384
echo $n_redirected_packets
echo $time_threshold
echo $count_min_size

# Update data plane parameters
sed -i -e 's|MAX_PACKETS=[^;]*|MAX_PACKETS='$n_redirected_packets'|' ../src/include/header.p4
sed -i -e 's|COUNT_MIN_SIZE=[^;]*|COUNT_MIN_SIZE='$count_min_size'|' ../src/include/header.p4
sed -i -e 's|TIME_THRESHOLD=[^;]*|TIME_THRESHOLD='$time_threshold'|' ../src/include/header.p4

# Create the snort log folders
mkdir ../snort/logs

# Emulate with each PCAP in the CIC-IDS 2017 dataset
for pcap in ../../CICIDS2017-PCAPS/*; do
	mkdir ../snort/logs/eth0
	mkdir ../snort/logs/hsnort-eth1
	mkdir ../snort/logs/hsnort-eth2
	mkdir ../snort/logs/hsnort-eth3
	mkdir ../snort/logs/hsnort-eth4

	pcap_name=$(echo $pcap | sed "s/.*\///")
	sed -i -e 's|CICIDS2017-PCAPS\/[^"]*|CICIDS2017-PCAPS/'$pcap_name'|' $config_file

	# Run the experiment
	cd ../src
	make clean
	make TEST_JSON=$config_file > $output_folder"output.txt"

	weekday=$(echo $pcap_name | sed "s|-.*||")
	mkdir $output_folder/$weekday
	mv $output_folder"output.txt" $output_folder/$weekday

	sudo chmod -R a+rwx ../snort/logs/*
	cp -r ../snort/logs/* $output_folder/$weekday
	rm -r ../snort/logs/*

	cd ../testing
done;

cd ../src
make clean

stty erase ^H
