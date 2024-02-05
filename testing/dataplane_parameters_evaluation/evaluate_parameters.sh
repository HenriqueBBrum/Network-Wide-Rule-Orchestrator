#!/bin/bash
scriptdir="$(dirname "$0")"
cd "$scriptdir"

# File used to evaluate the parameters of the dataplane

if [ $# -lt 1 ]
then
	echo "Missing arguments"
	exit 1
fi

output_folder=$1
ruleset_folder=$2

if [ ! -d $output_folder ]
then
	echo "Folder "$output_folder" does not exist"
	exit 1
fi

if [ -z $ruleset_folder ]
then
	ruleset_folder="../snort/rules/snort3-registered"
fi

# Run an experiment with each one of the following parameters:
for packets_to_clone in {10,25,50,100,200,400,800}; do
	for countmin_time_threshold in {10,25,50}; do
		for countmin_width in {256,512,1024,4096,16834}; do
			results_folder=${output_folder}/${packets_to_clone}_${countmin_time_threshold}_${countmin_width}_registered/
			mkdir $results_folder
			./run_parameter_experiment.sh $results_folder $ruleset_folder $packets_to_clone $countmin_time_threshold $countmin_width
		done;
	done;
done;
