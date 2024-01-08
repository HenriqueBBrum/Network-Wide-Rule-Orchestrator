#!/bin/bash

if [ $# -lt 2 ]
then
	echo "No arguments provided"
	exit 1
fi

parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

topology=$1
output_folder=$2
rule_distribution_scheme=$3

ruleset_folder=$4

table_entries="../src/p4_table_entries.config"


if [ ! -d $output_folder ]
then
	echo "Folder "$output_folder" does not exist"
	exit 1
fi

if [ -z $rule_distribution_scheme ]
then
	rule_distribution_scheme="distributed"
fi

if [ -z $ruleset_folder ]
then
	ruleset_folder="../snort/rules/snort3-registered"
fi


# Update topology in Makefile
sed -i -e 's|TOPO = topologies/[^/"]*|TOPO = topologies/'$topology'|' ../src/Makefile


config_file="$parent_path""/experiment_configuration/""$topology"".json"

# Update rule distribution scheme in the configuration file
if [ $rule_distribution_scheme == "simple" ]; then
	table_entries="../src/p4onids_compiled_rules.config"
fi
sed -i -e 's|\"rule_distribution_scheme\": [^,]*|\"rule_distribution_scheme\": \"'$rule_distribution_scheme'\"|' $config_file
sed -i -e 's|\"table_entries\": [^,]*|\"table_entries\": \"'$table_entries'\"|' $config_file

# Update the rule path in the configuration file
sed -i -e 's|--rule-path [^ "]*|--rule-path '$ruleset_folder'|' $config_file

# Create the snort log folders
mkdir ../snort/logs


# Update the data plane time_threshold parameter
time_threshold=10
sed -i -e 's|TIME_THRESHOLD=[^;"]*|TIME_THRESHOLD='$time_threshold'|' ../src/include/header.p4

# Emulate with each PCAP in the CIC-IDS 2017 dataset
for pcap in ../../CICIDS2017-PCAPS/*; do
	mkdir ../snort/logs/eth0
	if [ $topology != "parameters_eval" ]; then
		mkdir ../snort/logs/hsnort-eth1
		mkdir ../snort/logs/hsnort-eth2
		mkdir ../snort/logs/hsnort-eth3
		if [ $topology != "linear" ]; then
			mkdir ../snort/logs/hsnort-eth4
		fi 
	fi
	pcap_name=$(echo $pcap | sed "s/.*\///")
	sed -i -e 's|CICIDS2017-PCAPS\/[^\"]*|CICIDS2017-PCAPS/'$pcap_name'|' $config_file
	
	weekday=$(echo $pcap_name | sed "s|-.*||")
	if [ $weekday == "Monday" ]; then
		n_redirected_packets=200
		count_min_size=16384
	elif [ $weekday == "Tuesday" ]; then
		n_redirected_packets=100
		count_min_size=16384
	elif [ $weekday == "Wednesday" ]; then
		n_redirected_packets=25
		count_min_size=16384
	elif [ $weekday == "Thursday" ]; then
		n_redirected_packets=50
		count_min_size=4096
	elif [ $weekday == "Friday" ]; then
		n_redirected_packets=25
		count_min_size=4096
	fi

	echo $time_threshold
	echo $n_redirected_packets
	echo $count_min_size
	# Update data plane parameters
	sed -i -e 's|MAX_PACKETS=[^;"]*|MAX_PACKETS='$n_redirected_packets'|' ../src/include/header.p4
	sed -i -e 's|COUNT_MIN_SIZE=[^;"]*|COUNT_MIN_SIZE='$count_min_size'|' ../src/include/header.p4

	# Run the experiment
	cd ../src
	make clean
	make TEST_JSON=$config_file > $output_folder"output.txt"

	mkdir $output_folder${weekday}
	mv $output_folder"output.txt" $output_folder${weekday}

	sudo chmod -R a+rwx ../snort/logs/*
	cp -r ../snort/logs/* $output_folder/"${weekday}"
	rm -r ../snort/logs/*

	cd ../testing
done;

cd ../src
make clean

stty erase ^H
