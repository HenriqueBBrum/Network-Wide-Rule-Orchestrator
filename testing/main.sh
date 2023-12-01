#!/bin/bash

if [ $# -lt 2 ]
then
	echo "No arguments provided"
	exit 1
fi

parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

topology=$1
output_folder=$2
ruleset_folder=$3


if [ ! -d $output_folder ]
then
	echo "Folder "$output_folder" does not exist"
	exit 1
fi

if [ -z $ruleset_folder ]
then
	ruleset_folder="../snort/rules/snort3-registered"
fi



for size in {512,1024,4096,16348}; do

	results_folder=${output_folder}10_50_${size}_registered/
	mkdir $results_folder
	./run_experiment.sh $topology $results_folder 10 50 $size $ruleset_folder
done;
