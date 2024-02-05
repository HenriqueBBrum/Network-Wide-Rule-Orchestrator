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

table_entries_file="../../src/p4_table_entries_random.config"
amt_of_table_entries=$(wc -l < $table_entries_file)

table_entries_file="../src/p4_table_entries_random.config"

# Run an experiment in each one of the following scenarios:
for topology in {"linear","tree"}; do
	for table_entries_distribution_algorithm in {"simple","firstfit","bestfit"}; do
		for available_space in {100,75,50,25}; do
			a=$((available_space*amt_of_table_entries))
			amount_of_space_per_sw=$(echo $(( a%100? a/100+1:a/100 )))
			
			results_folder=${output_folder}/${topology}_${table_entries_distribution_algorithm}_${available_space}_registered_random/
			mkdir $results_folder

			./run_final_eval_experiment.sh $results_folder $ruleset_folder $table_entries_file $topology $table_entries_distribution_algorithm $amount_of_space_per_sw 
		done;
	done;
done;
