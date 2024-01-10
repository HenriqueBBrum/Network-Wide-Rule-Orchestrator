#!/bin/bash
scriptdir="$(dirname "$0")"
cd "$scriptdir"

if [ $# -lt 1 ]
then
	echo "No arguments provided"
	exit 1
fi

parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
snort_folder=../../snort/
src_folder=../../src/


topology="parameters_eval"
output_folder=$1

n_redirected_packets=$2
time_threshold=$3
count_min_size=$4

ruleset_folder=$5


if [ ! -d $output_folder ]
then
	echo "Folder "$output_folder" does not exist"
	exit 1
fi

# Check if variables were set up; otherwise use default value
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


if [ -z $ruleset_folder ]
then
	ruleset_folder=../snort/rules/snort3-registered # Only ../snort since this is used in  the src folder
fi


# Update topology in Makefile
sed -i -e 's|TOPO = topologies/[^/"]*|TOPO = topologies/'$topology'|' "$src_folder"Makefile

# Update data plane parameters
sed -i -e 's|MAX_PACKETS=[^;"]*|MAX_PACKETS='$n_redirected_packets'|' "$src_folder"include/header.p4
sed -i -e 's|TIME_THRESHOLD=[^;"]*|TIME_THRESHOLD='$time_threshold'|' "$src_folder"include/header.p4
sed -i -e 's|COUNT_MIN_SIZE=[^;"]*|COUNT_MIN_SIZE='$count_min_size'|' "$src_folder"include/header.p4

config_file="$parent_path"/../experiment_configuration/"$topology".json

# Update rule path in configuration file
sed -i -e 's|--rule-path [^ "]*|--rule-path '$ruleset_folder'|' $config_file

# Create snort log folders
mkdir "$snort_folder"logs

# Emulate with each PCAP in the CICIDS 2017 dataset
for pcap in ../../../CICIDS2017-PCAPS/*; do
	mkdir "$snort_folder"logs/eth0
	pcap_name=$(echo $pcap | sed "s/.*\///")
	sed -i -e 's|CICIDS2017-PCAPS\/[^\"]*|CICIDS2017-PCAPS/'$pcap_name'|' $config_file

	cd $src_folder
	make clean
	make TEST_JSON=$config_file > "$output_folder"output.txt

	IFS='-' read -r -a array <<< $pcap_name

	cd $parent_path
	mkdir $output_folder${array[0]}
	mv "$output_folder"output.txt $output_folder${array[0]}

	sudo chmod -R a+rwx "$snort_folder"logs/*
	cp -r "$snort_folder"logs/* $output_folder/"${array[0]}"
	rm -r "$snort_folder"logs/*
done;

cd $src_folder
make clean

stty erase ^H
