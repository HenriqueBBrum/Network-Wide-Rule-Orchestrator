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
	for table_entries_distribution_scheme in {"simple","firstfit","bestfit"}; do
		table_entries_file="../src/p4_table_entries.config"
		if [ $table_entries_distribution_scheme == "simple" ]; then
			table_entries_file="../src/p4onids_compiled_rules.config"
		fi
		for available_space in {100,66,33}; do
			amt_of_table_entries=$(wc -l < $table_entries_file)
			div=$(bc <<< "scale=2; $available_space/100")
			amount_of_space_per_sw=$(bc <<< "scale=2; $amt_of_table_entries*$div")
			amount_of_space_per_sw=$(printf "%.0f" $amount_of_space_per_sw)
			results_folder=${output_folder}/${topology}_${table_entries_distribution_scheme}_${available_space}_registered/
			mkdir $results_folder

			./run_final_eval_experiment.sh $results_folder $ruleset_folder $table_entries_file $topology $table_entries_distribution_scheme $amount_of_space_per_sw 
		done;
	done;
done;
