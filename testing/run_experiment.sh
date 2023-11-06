#!/bin/bash

parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

topology=$1
output_folder=$2

if [ $# -lt 2 ]
then 
	echo "No arguments provided"
	exit 1
fi

config_file="$parent_path""/experiment_configuration/""$topology"".json"


for pcap in ../../CICIDS2017-PCAPS/*; do
	pcap_name=$(echo $pcap | sed "s/.*\///")
	sed -i -e 's|CICIDS2017-PCAPS\/[^\"]*|CICIDS2017-PCAPS/'$pcap_name'|' $config_file
	

	cd ../src
	make clean
	make TEST_JSON=$config_file

	IFS='-' read -r -a array <<< "$pcap_name"

	mkdir $output_folder${array[0]}

	cp -r ../snort/logs/* $output_folder/"${array[0]}"

	rm ../snort/logs/eth0/*
	rm ../snort/logs/hsnort-eth1/*
	rm ../snort/logs/hsnort-eth2/*

	cd ../testing

done;

stty erase ^H