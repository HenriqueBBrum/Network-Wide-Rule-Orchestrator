#!/bin/bash

# File used to evaluate the parameters of the dataplane

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


for time_threshold in {10,25,50}; do
	for size in {256,512,1024,4096,16834}; do
		for packets_redirected in {10,25,50,100,200,400,800}; do
			results_folder=${output_folder}${packets_redirected}_${time_threshold}_${size}_registered/
			mkdir $results_folder
			./run_experiment.sh $topology $results_folder $packets_redirected $time_threshold $size $ruleset_folder
		done;
	done;
done;