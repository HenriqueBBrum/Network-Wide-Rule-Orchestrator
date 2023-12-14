import json
import os
import argparse
from collections import Counter
import csv
# import pandas


baseline_packets_redirected = {"registered": {"Monday": 11709971, "Tuesday": 11551954, "Wednesday": 13788878, "Thursday": 9322025, "Friday": 9997874}}

def parse_args():
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--input-folder', help='Folder containing the parameters evaluation folder', type=str, required=True)
    parser.add_argument('--baseline-folder', help='Folder containing the baseline results', 
    	type=str, default="../baseline_alerts/CICIDS2017/alerts_snort3-registered", required=False)

    return parser.parse_args()


def main(args):
	baseline_data = read_baseline(args.baseline_folder)
	csv_data = []
	for item in os.listdir(args.input_folder):
		item_fullpath = os.path.join(args.input_folder, item)
		if os.path.isfile(item_fullpath):
			continue

		folder_name_elements = item.split("_")
		experiments_data = read_experiments_data(item_fullpath)

		for key, data in experiments_data.items():
			csv_line = {}

			csv_line["PCAP"] = key
			csv_line["Packets to redirect (N)"] = folder_name_elements[0]
			csv_line["Time threshold (T)"] = folder_name_elements[1]
			csv_line["Count-min scketches size (W)"] = folder_name_elements[2]
			csv_line["Alerts"] = len(data["alerts"])
			csv_line["Percent of alerts from baseline"] =  len(data["alerts"])/len(baseline_data[key]["alerts"])
			csv_line["Packets redirected"] = data["packets_redirected"]
			csv_line["Percent of packets redirected from baseline"] =  \
					 data["packets_redirected"]/baseline_packets_redirected[folder_name_elements[3]][key]
			csv_data.append(csv_line)

	keys = csv_data[0].keys()
	with open('parameters_evaluation.csv', 'w') as file:
	    w = csv.DictWriter(file, keys)
	    w.writeheader()
	    for line in csv_data:
	    	w.writerow(line)
			


def read_experiments_data(experiments_data_folder):
	folder_data = {}
	for item in os.listdir(experiments_data_folder):
		item_fullpath = os.path.join(experiments_data_folder, item)
		if os.path.isfile(item_fullpath):
			continue

		no_duplicates_data = {}
		raw_data = []
		rules_counter = Counter()
		for subdir in os.listdir(item_fullpath):
			if os.path.isfile(os.path.join(item_fullpath, subdir)):
				continue

			alert_file = os.path.join(item_fullpath, subdir) + "/alert_json.txt"
			data, counter, no_duplicates =  read_snort_alerts(alert_file)
			raw_data.extend(data)
			rules_counter.update(counter)
			for key, value in no_duplicates.items():
				if key not in no_duplicates_data:
					no_duplicates_data[key] = value

		packets_redirected = read_amt_of_redirected_pkts(os.path.join(item_fullpath, "output.txt"))
		folder_data[item]={"alerts": no_duplicates_data, "counter": rules_counter, "packets_redirected": packets_redirected}
	return folder_data

def read_snort_alerts(alert_filepath):
	no_duplicates_data = {}
	data = []
	counter = Counter()
	file = open(alert_filepath)
	if os.path.getsize(alert_filepath) > 0:
		try:
			for line in file.readlines():
				parsed_line = json.loads(line)
				data.append(parsed_line)

				entry_key = str(parsed_line["pkt_num"]) + parsed_line["rule"] + parsed_line["timestamp"]
				if entry_key not in no_duplicates_data:
					no_duplicates_data[entry_key] = line
				
				counter[parsed_line["rule"]]+=1
		except Exception as e:
			print("JSON error: ", e)
	file.close()
	return data, counter, no_duplicates_data

def read_amt_of_redirected_pkts(p4_output_filepath):
	packets_redirected = 0
	try:
		with open(p4_output_filepath) as file:
			packets_redirected = 0
			get_data = False
			previous_line = ""
			for line in file:
				if "Counter name:  MyEgress.cloned_to_ids" in previous_line and "Index (port):  index: 2" in line:
					get_data = True
				
				if "packet_count" in line and get_data==1:
					packets_redirected += int(line.split()[1])
					get_data = False

				previous_line = line
	except:
		print("No output file in this folder")

	return packets_redirected


def read_baseline(baseline_folder):
	baseline_data = {}
	for alert_file in os.listdir(baseline_folder):
		item_fullpath = os.path.join(baseline_folder, alert_file)

		raw_data, rules_counter, no_duplicates_data =  read_snort_alerts(item_fullpath)
		baseline_data[alert_file.split(".")[0]]={"alerts": no_duplicates_data, "counter": rules_counter}
	
	return baseline_data

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
