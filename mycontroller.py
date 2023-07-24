import argparse
import os
import sys
import json
import networkx as nx
import matplotlib.pyplot as plt
from networkx.drawing.nx_agraph import write_dot, graphviz_layout
from time import sleep

import grpc

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 'utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

def parse_args():
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, required=False, default='./build/main.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, required=False, default='./build/main.json')
    parser.add_argument('--network-info', help='Network information',
                        type=str, required=True)
    parser.add_argument('--table-entries', help='Table entries file',
                        type=str, required=True)
    parser.add_argument('--start-nodes-strategy', help='BMv2 JSON file from p4c',
                        type=str, required=False, default='PRIORITIZE_OUTER')

    return parser.parse_args()


def main(args):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(args.p4info_file_path)

    with open(network_information_file) as f:
        network_info = json.load(f)

    with open(rules_filepath) as rule_file:
        rules = rule_file.read().splitlines()

    # !!!!!!!!!!!!!!!Validate swithc name. Name must be 's<non negative integer>'
    device_table_entries_map = distribute_rules(network_info, rules, strategy)

    try:
        # Create a switch connection object for s1 and s2; this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        switches = {}
        for switch_id, rules in device_table_entries_map.items():
            id = int(switch_id.split('s')[0])
            switch = p4runtime_lib.bmv2.Bmv2SwitchConnection( 
                name=switch_id,
                address='127.0.0.1:5005'+str(id),
                device_id=id,
                proto_dump_file='logs/'+switch_id+'-p4runtime-requests.txt')


            # Send master arbitration update message to establish this controller as master
            switch.MasterArbitrationUpdate()
            print("Installed P4 Program using SetForwardingPipelineConfig on switch "+switch_id)
            switch.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=args.bmv2_json)
            switches[switch_id] = switch
            write_rules(p4info_helper, switch, rules)   
            read_table_rules()         

        # # TODO Uncomment the following two lines to read table entries from s1 and s2
        # readTableRules(p4info_helper, s1)
        # readTableRules(p4info_helper, s2)

        while True:
            sleep(2)
            print('\n----- Reading table entries -----')
            
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
        device_table_entries_map[node] = rules[l, l+end]

    return device_table_entries_map



def write_rules(p4info_helper, switch, rules):
    for rule in rules:
        rule_fields = get_rule_fields(rule)

        if rule_fields["table_name"] == "ipv4_ids":
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_ids",
                match_fields={
                    "hdr.ip.v4.protocol": rule_fields["protocol"],
                    "hdr.ip.v4.srcAddr": (rule_fields["srcAddr"], rule_fields["srcMask"]),
                    "meta.srcPort":(rule_fields["srcPortLower"], rule_fields["srcPortUpper"]),
                    "hdr.ip.v4.dstAddr": (rule_fields["dstAddr"], rule_fields["dstMask"]),
                    "meta.dstPort": (rule_fields["dstPortLower"], rule_fields["dstPortUpper"]),
                    "meta.flags" (rule_fields["flags"], rule_fields["flagsMask"])
                },
                action_name="MyIngress."+rule_fields["action"],
                action_params={
                    "dst_id": tunnel_id,
                })
        else:
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv6_ids",
                priority=rule_fields["priority"]
                match_fields={
                    "hdr.ip.v6.nextHeader": rule_fields["protocol"],
                    "hdr.ip.v6.srcAddr": (rule_fields["srcAddr"], rule_fields["srcMask"]),
                    "meta.srcPort":(rule_fields["srcPortLower"], rule_fields["srcPortUpper"]),
                    "hdr.ip.v6.dstAddr": (rule_fields["dstAddr"], rule_fields["dstMask"]),
                    "meta.dstPort": (rule_fields["dstPortLower"], rule_fields["dstPortUpper"]),
                    "meta.flags" (rule_fields["flags"], rule_fields["flagsMask"])
                },
                action_name="MyIngress."+rule_fields["action"],
                action_params={
                    "port": rules_fields["new_port"],
                })

        switch.WriteTableEntry(table_entry)

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

    rule_fields["flags"] = rule_items[8].split("&&&")[0]
    rule_fields["flagsMask"] = rule_items[8].split("&&&")[1]

    rule_fields["new_port"] = rule_items[10]
    rule_fields["priority"] = rule_items[11]




def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print('\n----- Reading tables rules for %s -----' % sw.name)
    for response in sw.ReadTableEntries():
        for entity in response.entities:
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