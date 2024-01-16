#!/bin/bash
scriptdir="$(dirname "$0")"
cd "$scriptdir"

# File used to evaluate the parameters of the dataplane

if [ $# -lt 1 ]
then
	echo "No arguments provided"
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


for topology in {"linear","tree","ring"}; do
	for rule_distribution_scheme in {"simple","firstfit","bestfit"}; do
		for available_space in {100,66,33}; do
			amt_of_table_entries=$(wc -l < $table_entries_file)
			amount_of_space_per_sw=$((amt_of_table_entries*(100/available_space)))
			echo $amount_of_space_per_sw
			results_folder=${output_folder}${topology}_${rule_distribution_scheme}_${available_space}_registered/
			mkdir $results_folder
			# ./run_final_eval_experiment.sh $topology $results_folder $rule_distribution_scheme $amount_of_space_per_sw $table_entries_file $ruleset_folder
		done;
	done;
done;
