import json
import os
import argparse
from collections import Counter


def parse_args():
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--input-folder', help='Folder containing the experiments json output files', type=str, required=True)
    parser.add_argument('--baseline-folder', help='Folder containing the baseline results', 
    	type=str, default="../baseline_alerts/CICIDS2017/alerts_snort3-community", required=False)

    return parser.parse_args()


def main(args):
	print(args)
	experiments_data = read_experiments_data(args.input_folder)
	print(experiments_data.keys())
	compare_with_baseline(experiments_data, args.baseline_folder)


def read_experiments_data(experiments_data_folder):
	folder_data = {}
	for item in os.listdir(experiments_data_folder):
		item_fullpath = os.path.join(experiments_data_folder, item)
		if os.path.isfile(item_fullpath):
			continue

		no_duplicates_data = {}
		raw_data = []
		rules_counter = Counter()
		print(item)
		for subdir in os.listdir(item_fullpath):
			alert_file = os.path.join(item_fullpath, subdir) + "/alert_json.txt"
			data, counter =  read_snort_alerts(alert_file)
			raw_data.extend(data)
			rules_counter.update(counter)

		print(len(raw_data))
		print(rules_counter.most_common(5))
		folder_data[item]=raw_data
	return folder_data

def read_snort_alerts(alert_file_path):
	no_duplicates_data = {}
	data = []
	counter = Counter()
	file = open(alert_file_path)
	if os.path.getsize(alert_file_path) > 0:
		try:
			for line in file.readlines():
				parsed_line = json.loads(line)
				data.append(parsed_line)

				entry_key = str(parsed_line["pkt_num"]) + parsed_line["rule"]
				if entry_key not in no_duplicates_data:
					no_duplicates_data[entry_key] = line
				else:
					print(no_duplicates_data[entry_key])
					print(line)
					print("Error!!!!!!!!!!!! Duplicated packet")
					exit(-1)
				 
				counter[parsed_line["rule"]]+=1
		except Exception as e:
			print("JSON error: ", e)
	file.close()
	return data, counter

def compare_with_baseline(experiments_data, baseline_folder):
	baseline_data = {}
	for alert_file in os.listdir(baseline_folder):
		raw_data = []
		rules_counter = Counter()
		item_fullpath = os.path.join(baseline_folder, alert_file)

		print(alert_file)
		data, counter, no_duplicates_data =  read_snort_alerts(item_fullpath)
	
		print(len(raw_data), len(unique_data))
		print(rules_counter.most_common(5))
		baseline_data[item]=raw_data

	for pcap_name, data in baseline_data.items():
		index = 0
		while index < len(data):
			print(data[index])
			print(experiments_data[pcap_name][index])
			break



if __name__ == '__main__':
    args = parse_args()

    if not os.path.exists(args.input_folder):
        parser.print_help()
        print("\nFolder not found: %s\n" % args.p4info)
        parser.exit(1)

    if args.baseline_folder and not os.path.exists(args.baseline_folder):
    	parser.print_help()
    	print("\nFolder not found: %s\n" % args.p4info)
    	parser.exit(1)

    main(args)
