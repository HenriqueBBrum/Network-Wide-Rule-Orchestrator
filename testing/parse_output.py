import json
import os
import argparse
from collections import Counter


def parse_args():
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--input_folder', help='Folder containing the experiments json output files', type=str, required=True)
    parser.add_argument('--baseline_folder', help='Folder containing the baseline results', type=str, required=False)

    return parser.parse_args()


def main(args):
	print(args)
	folder_data = {}
	for item in os.listdir(args.input_folder):
		item_fullpath = os.path.join(args.input_folder, item)
		if os.path.isfile(item_fullpath):
			continue

		print(item_fullpath)

		unique_data = {}
		raw_data = []
		rules_counter = Counter()
		for subdir in os.listdir(item_fullpath):
			alert_file = os.path.join(item_fullpath, subdir) + "/alert_json.txt"
			file = open(alert_file)
			if os.path.getsize(alert_file) > 0:
				try:
					for line in file.readlines():
						parsed_line = json.loads(line)
						raw_data.append(parsed_line)

						entry_key = str(parsed_line["pkt_num"]) + parsed_line["rule"]
						if entry_key not in unique_data:
							unique_data[entry_key] = 1
						else:
						 	unique_data[entry_key]+=1
						 
						rules_counter[parsed_line["rule"]]+=1
				except Exception as e:
					print("JSON error: ", e)
			file.close()

		print(len(raw_data), len(unique_data))
		print(rules_counter.most_common(5))





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
