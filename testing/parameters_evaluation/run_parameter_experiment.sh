# Evaluate one dataplane parameter configuration

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

# packets_to_clone=$3
# countmin_aging_threshold=$4
# countmin_width=$5

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
if [ -z $packets_to_clone ]
then
	packets_to_clone=200
fi

if [ -z $countmin_aging_threshold ]
then
	countmin_aging_threshold=10
fi

echo $3

if [ -z $countmin_width ]
then
	countmin_width=16384
fi

config_file=$parent_path"/../experiment_configuration/"$topology".json"

# Update rule path in the configuration file
sed -i -e 's|--rule-path [^ ]*|--rule-path '$ruleset_folder'|' $config_file

# Update the topology in Makefile
sed -i -e 's|TOPO = topologies/[^/]*|TOPO = topologies/'$topology'|' $src_folder"/Makefile"

# Update the data plane parameters
sed -i -e 's|MAX_PACKETS=[^;]*|MAX_PACKETS='$packets_to_clone'|' $src_folder"/include/header.p4"
sed -i -e 's|COUNTMIN_AGING_THRESHOLD^;]*|COUNTMIN_AGING_THRESHOLD='$countmin_aging_threshold'|' $src_folder"/include/header.p4"
sed -i -e 's|COUNTMIN_WIDTH=[^;]*|COUNTMIN_WIDTH='$countmin_width'|' $src_folder"/include/header.p4"

# Create snort log folders
mkdir $snort_folder"logs"

# Emulate with each PCAP in the CICIDS2017 dataset
for pcap in /home/ubuntu/NFSDatasets/CICIDS2017/Friday*; do
	mkdir $snort_folder"logs/eth0"

	pcap_name=$(echo $pcap | sed "s/.*\///")
	sed -i -e 's|CICIDS2017\/[^"]*|CICIDS2017/'$pcap_name'|' $config_file

	# Run the experiment
	cd $src_folder
	make clean
	make TEST_JSON=$config_file &> $output_folder"/stdout_output.txt"

	# Save the results of the experiment
	cd $parent_path
	weekday=$(echo $pcap_name | sed "s|-.*||")
	mkdir $output_folder/$weekday"_"$3
	mv $output_folder"/stdout_output.txt" $output_folder/$weekday"_"$3

	# Clean snort outputs
	sudo chmod -R a+rwx "$snort_folder"/logs/*
	cp -r "$snort_folder"/logs/* $output_folder/$weekday"_"$3
	rm -r "$snort_folder"/logs/*
done;

cd $src_folder
make clean

stty erase ^?
