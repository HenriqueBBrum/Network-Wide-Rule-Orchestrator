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


for n_cloned_packets in {10,25,50,100,200,400,800}; do
	for t_count_min_ageing_time_threshold in {10,25,50}; do
		for w_count_min_size in {256,512,1024,4096,16834}; do
			results_folder=${output_folder}/${n_cloned_packets}_${t_count_min_ageing_time_threshold}_${w_count_min_size}_registered/
			mkdir $results_folder
			./run_parameter_experiment.sh $results_folder $ruleset_folder $n_cloned_packets $t_count_min_ageing_time_threshold $w_count_min_size
		done;
	done;
done;
