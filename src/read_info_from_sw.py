import argparse
import os
import sys
import json
import networkx as nx
import matplotlib.pyplot as plt

from networkx.drawing.nx_agraph import write_dot, graphviz_layout
from time import sleep
from itertools import islice


import grpc

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections


def parse_args():
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, required=False, default='./build/main.p4.p4info.txt')
    parser.add_argument('--bmv2_json', help='BMv2 JSON file from p4c',
                        type=str, required=False, default='./build/main.json')
    parser.add_argument('--network_info', help='Network information',
                        type=str, required=True)
   

    return parser.parse_args()


def main(args):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(args.p4info)

    with open(args.network_info) as f:
        network_info = json.load(f)

    # !!!!!!!!!!!!!!!Validate switch name. Name must be 's<non negative integer>'
    switches = list(network_info["switches"].items())
    print(switches)
    try:
        # Create a switch connection object for s1 and s2; this is backed by a P4Runtime gRPC connection.
	    
        switch_map = {}
        for switch in switches:
        	num_id = int(switch[0].split('s')[1])
        	
	        switch_connection = p4runtime_lib.bmv2.Bmv2SwitchConnection( 
	            name=switch[0],
	            address='127.0.0.1:5005'+str(num_id),
	            device_id=num_id-1,
	            proto_dump_file='logs/'+switch[0]+'-p4runtime-requests.txt')    

	        switch_map[switch[0]] = switch_connection      

        while True:
            print('\n----- Reading table entries -----')
            for switch_id, switch_connection in switch_map.items():
                readTableRules(p4info_helper, switch_connection)
            sleep(10)
            os.system('cls||clear')

            
    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)





def readTableRules(p4info_helper, switch):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print('\n----- Reading tables rules for %s -----' % switch.name)
    count = 0
    for response in switch.ReadTableEntries():
        for entity in response.entities:
            if(count > 10):
                return
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print('%s: ' % table_name, end=' ')
            for m in entry.match:
                print(p4info_helper.get_match_field_name(table_name, m.field_id), end=' ')
                print('%r' % (p4info_helper.get_match_field_value(m),), end=' ')
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print('->', action_name, end=' ')
            for p in action.params:
                print(p4info_helper.get_action_param_name(action_name, p.param_id), end=' ')
                print('%r' % p.value, end=' ')
            print()
            count+=1

if __name__ == '__main__':
    args = parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)

    main(args)