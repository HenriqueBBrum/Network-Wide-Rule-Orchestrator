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
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 'utils/'))
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
    parser.add_argument('--table_entries', help='Table entries file',
                        type=str, required=True)
    parser.add_argument('--start_nodes_strategy', help='BMv2 JSON file from p4c',
                        type=str, required=False, default='PRIORITIZE_OUTER')

    return parser.parse_args()


def main(args):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(args.p4info)

    with open(args.network_info) as f:
        network_info = json.load(f)

    with open(args.table_entries) as rule_file:
        rules = rule_file.read().splitlines()

    # !!!!!!!!!!!!!!!Validate switch name. Name must be 's<non negative integer>'
    device_table_entries_map = distribute_rules(network_info, rules, args.start_nodes_strategy)
    print(device_table_entries_map.keys())
    try:
        # Create a switch connection object for s1 and s2; this is backed by a P4Runtime gRPC connection.
        switches = {}
        for switch_id, rules in device_table_entries_map.items():
            num_id = int(switch_id.split('s')[1])
            switch = p4runtime_lib.bmv2.Bmv2SwitchConnection( 
                name=switch_id,
                address='127.0.0.1:5005'+str(num_id),
                device_id=num_id-1,
                proto_dump_file='logs/'+switch_id+'-p4runtime-requests.txt')

            # Send master arbitration update message to establish this controller as master
            switch.MasterArbitrationUpdate()
            print("Installed P4 Program using SetForwardingPipelineConfig on switch "+switch_id)
            switch.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=args.bmv2_json)
            switches[switch_id] = switch
            # Writes for each switch its rules
            write_rules(p4info_helper, switch, rules)   

        while True:
            print('\n----- Reading table entries -----')
            for switch_id, switch_connection in switches.items():
                readTableRules(p4info_helper, switch_connection)
            sleep(10)
            os.system('cls||clear')

            
    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()


# Determines the subset of rules for each device according to the least safe path from the inital set of nodes
def distribute_rules(network_info, rules, strategy):
    device_table_entries_map = {}
    initial_nodes, not_initial_nodes = [], []

    metric = "hops_from_internet" if strategy == "PRIORITIZE_OUTER" else "hops_from_host"

    network = nx.DiGraph()
    network.add_node("start")
    # Separates the initial nodes and determine the subset of rules for them
    for node, data in network_info["switches"].items():
        network.add_node(node, **data)

        if data[metric] == 0:
            initial_nodes.append(node)
            network.add_edge("start", node, weight=0)
            end = len(rules) if data["free_table_entries"] > len(rules) else data["free_table_entries"]
            device_table_entries_map[node] = rules[0:end]
        else:
            not_initial_nodes.append(node)

    # Creates the edges according to the existent links
    for link in network_info["links"]:
        if 'h' in link[0] or 'h' in link[1]:
            continue     
        network.add_edge(link[0], link[1], weight=network.nodes[link[0]]["free_table_entries"])
        network.add_edge(link[1], link[0], weight=network.nodes[link[1]]["free_table_entries"])
    
    # Calculates the least safe path lenght and determine the subset of rules for "node"
    for node in not_initial_nodes:
        l = nx.shortest_path_length(network, source="start", target=node, weight="weight")
        end = len(rules) if network_info["switches"][node]["free_table_entries"] > len(rules) else network_info["switches"][node]["free_table_entries"]
        device_table_entries_map[node] = rules[l: l+end]

    return device_table_entries_map

# Parses table entires file and writes them to the corresponding switch
def write_rules(p4info_helper, switch, rules):
    for rule in rules:
        rule_fields = get_rule_fields(rule)
        if rule_fields["table_name"] == "ipv4_ids":
            # Remove "don't care entries" (e.g. 0.0.0.0 IP or 0-65535 port range) because P4Runtime does not accept them
            match_fields = build_match_fields(rule_fields) 
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_ids",
                priority=int(rule_fields["priority"]),
                match_fields=match_fields,
                action_name="MyIngress."+rule_fields["action"])
        else:
            match_fields = build_match_fields(rule_fields, 6)
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv6_ids",
                priority=int(rule_fields["priority"]),
                match_fields=match_fields,
                action_name="MyIngress."+rule_fields["action"])
        switch.WriteTableEntry(table_entry)
        
# Parses a table entry from the rule compiler list and saves the meaningful fields to a dict
def get_rule_fields(rule):
    rule_fields = {}
    rule_items = rule.split(" ")
    
    rule_fields["table_name"] = rule_items[1]
    rule_fields["action"] = rule_items[2]
    rule_fields["protocol"] = rule_items[3]

    rule_fields["srcAddr"] = rule_items[4].split("&&&")[0]
    rule_fields["srcMask"] = rule_items[4].split("&&&")[1]

    rule_fields["srcPortLower"] = rule_items[5].split("->")[0]
    rule_fields["srcPortUpper"] = rule_items[5].split("->")[1]

    rule_fields["dstAddr"] = rule_items[6].split("&&&")[0]
    rule_fields["dstMask"] = rule_items[6].split("&&&")[1]

    rule_fields["dstPortLower"] = rule_items[7].split("->")[0]
    rule_fields["dstPortUpper"] = rule_items[7].split("->")[1]

    rule_fields["flags"] = rule_items[8]

    rule_fields["priority"] = rule_items[10]

    return rule_fields

# Don't add table matches with "don't care values", including 0.0.0.0 IPs and 0->65535 port ranges
def build_match_fields(rule_fields, ip_version=4):
    match_fields = {}
    match_fields["meta.protocol"] = int(rule_fields["protocol"], base=16)
    if rule_fields["srcAddr"] != "0.0.0.0":
        match_fields[f"hdr.ip.v{ip_version}.srcAddr"] = (rule_fields["srcAddr"], rule_fields["srcMask"])

    if rule_fields["srcPortLower"] != "0" or rule_fields["srcPortUpper"] != "65535":
       match_fields["meta.srcPort"] = (int(rule_fields["srcPortLower"]), int(rule_fields["srcPortUpper"]))

    if rule_fields["dstAddr"] != "0.0.0.0":
        match_fields[f"hdr.ip.v{ip_version}.dstAddr"] = (rule_fields["dstAddr"], rule_fields["dstMask"])

    if rule_fields["dstPortLower"] != "0" or rule_fields["dstPortUpper"] != "65535":
       match_fields["meta.dstPort"] = (int(rule_fields["dstPortLower"]), int(rule_fields["dstPortUpper"]))

    match_fields["meta.flags"] = int(rule_fields["flags"], 2)

    return match_fields
    

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