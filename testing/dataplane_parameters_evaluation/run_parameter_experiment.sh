#!/bin/bash
scriptdir="$(dirname "$0")"
cd $scriptdir

if [ $# -lt 1 ]
then
	echo "Missing arguments"
	exit 1
fi

parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
snort_folder=../../snort/
src_folder=../../src/

output_folder=$1
ruleset_folder=$2
topology="parameters_eval"

n_cloned_packets=$3
t_count_min_ageing_time_threshold=$4
w_count_min_size=$5

if [ ! -d $output_folder ]
then
	echo "Folder "$output_folder" does not exist"
	exit 1
fi

if [ -z $ruleset_folder ]
then
	ruleset_folder=../snort/rules/snort3-registered/ # Only ../snort since this is used in the src folder
fi

# Check if variables were set up; otherwise use default value
if [ -z $n_cloned_packets ]
then
	n_cloned_packets=10
fi

if [ -z $t_count_min_ageing_time_threshold ]
then
	t_count_min_ageing_time_threshold=10
fi

if [ -z $w_count_min_size ]
then
	w_count_min_size=1024
fi

config_file=$parent_path"/../experiment_configuration/"$topology".json"

# Update rule path in configuration file
sed -i -e 's|--rule-path [^ ]*|--rule-path '$ruleset_folder'|' $config_file

# Update topology in Makefile
sed -i -e 's|TOPO = topologies/[^/]*|TOPO = topologies/'$topology'|' $src_folder"/Makefile"

# Update data plane parameters
sed -i -e 's|MAX_PACKETS=[^;]*|MAX_PACKETS='$n_cloned_packets'|' $src_folder"/include/header.p4"
sed -i -e 's|TIME_THRESHOLD=[^;]*|TIME_THRESHOLD='$t_count_min_ageing_time_threshold'|' $src_folder"/include/header.p4"
sed -i -e 's|COUNT_MIN_SIZE=[^;]*|COUNT_MIN_SIZE='$COUNT_MIN_SIZE'|' $src_folder"/include/header.p4"

# Create snort log folders
mkdir $snort_folder"/logs"

# Emulate with each PCAP in the CICIDS 2017 dataset
for pcap in ../../../CICIDS2017-PCAPS/*; do
	mkdir $snort_folder"/logs/eth0"

	pcap_name=$(echo $pcap | sed "s/.*\///")
	sed -i -e 's|CICIDS2017-PCAPS\/[^"]*|CICIDS2017-PCAPS/'$pcap_name'|' $config_file

	# Run the experiment
	cd $src_folder
	make clean
	make TEST_JSON=$config_file > $output_folder"/output.txt"

	cd $parent_path
	weekday=$(echo $pcap_name | sed "s|-.*||")
	mkdir $output_folder/$weekday
	mv $output_folder"/output.txt" $output_folder/$weekday

	sudo chmod -R a+rwx "$snort_folder"/logs/*
	cp -r "$snort_folder"/logs/* $output_folder/$weekday
	rm -r "$snort_folder"/logs/*
done;

cd $src_folder
make clean

stty erase ^H
