# FILE RESPONSIBLE FOR SPLITTING THE NIDS RULES TO THE SWITCHES AND OFFLOADING THE RULES TO THEM

import argparse
import os
import sys
import json
import networkx as nx
import matplotlib.pyplot as plt

from networkx.drawing.nx_agraph import write_dot, graphviz_layout
from time import sleep
from itertools import islice

import ipaddress
import grpc

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections


switches = {}



def install_rules(p4info, bmv2_json, network_info_file, table_entries_file, rule_distribution_scheme):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info)

    with open(network_info_file) as f:
        network_info = json.load(f)

    with open(table_entries_file) as f:
        rules = f.read().splitlines()

    switches_info, hosts_info = get_network_info(network_info)
    print(switches_info)
    print(hosts_info)
    parsed_rules = [get_rule_fields(rule) for rule in rules]
    ordered_rules = sorted(parsed_rules, key=lambda rule: rule['priority'], reverse=True)

    dag_topology = nx.DiGraph()
    dag_topology.add_node("start")

    for node, data in network_info["switches"].items():
        dag_topology.add_node(node, **data)
        if data["hops_from_source"] == 0:
            dag_topology.add_edge("start", node, weight=0)

    for link in network_info["links"]:
        if("h" in link[0]):
            dag_topology.add_edge(link[1], link[0]) 
        else:
            dag_topology.add_edge(link[0], link[1])


    table_entries_subsets = create_table_entries_subsets(dag_topology, switches_info, hosts_info, ordered_rules)
    ## Distributions calculated manualy
    ## LINEAR FF 1500
    device_table_entries_map = {}
    device_table_entries_map["s1"] = table_entries_subsets["generic"]
    for subset in table_entries_subsets["networks"].values():
        device_table_entries_map["s1"].extend(subset)
    for key, subset in table_entries_subsets.items():
        if (key!="generic" and key !="networks"):
            device_table_entries_map["s1"].extend(subset)

    device_table_entries_map["s2"] = []
    device_table_entries_map["s3"] = []
    device_table_entries_map["s4"] = []
    device_table_entries_map["s5"] = []
    ## END OF LINEAR FF 1500



    try:
        # Create a switch connection object for s1 and s2; this is backed by a P4Runtime gRPC connection.
        for switch_id, rules in device_table_entries_map.items():
            num_id = int(switch_id.split('s')[1])
            switch = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name=switch_id,
                address='127.0.0.1:5005'+str(num_id),
                device_id=num_id-1,
                proto_dump_file='logs/'+switch_id+'-p4runtime-requests_ids.txt')

            # Send master arbitration update message to establish this controller as master
            switch.MasterArbitrationUpdate()
            # print("Installed P4 Program using SetForwardingPipelineConfig on switch "+switch_id)
            # switch.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_json)
            switches[switch_id] = switch
            # Writes for each switch its rules
            write_rules(p4info_helper, switch, rules)
            read_table_rules(p4info_helper, switch)

    except KeyboardInterrupt:
        print("Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

def get_network_info(network_info):
    switches_info = {}
    hosts_info = {}
    for switch in network_info["switches"].keys():
        switches_info[switch] = []

    for link in network_info["links"]:
        if (link[0] == "hsource"):
            continue

        if("h" == link[0][0] and not "h" == link[1][0]):
            if (type(network_info["hosts"][link[0]]["ip"]) is list):
                switches_info[link[1]].extend(network_info["hosts"][link[0]]["ip"])
                for ip in network_info["hosts"][link[0]]["ip"]:
                    hosts_info[ip] = link[1]
            else:
                switches_info[link[1]].append(network_info["hosts"][link[0]]["ip"])
                hosts_info[network_info["hosts"][link[0]]["ip"]] = link[1]

    return switches_info, hosts_info

def create_table_entries_subsets(network_topology, switches_info, hosts_info, rules):
    table_entries_subsets = {key: [] for key in switches_info}
    table_entries_subsets["generic"] = []
    table_entries_subsets["networks"] = {}
    for rule in rules:
        if (rule["dstMask"]=="0.0.0.0"):
            table_entries_subsets["generic"].append(rule)
        elif(rule["dstMask"]=="255.255.255.255"):
            if (rule["dstAddr"]=="255.255.255.255"):
                table_entries_subsets["generic"].append(rule)
            else:
                table_entries_subsets[hosts_info[rule["dstAddr"]+"/24"]].append(rule)
        elif(rule["dstMask"]!="0.0.0.0" and rule["dstMask"]!="255.255.255.255"):
            dependent_switches = set()
            for host, switch in hosts_info.items():
                if (ipaddress.ip_address(host.split("/")[0]) in ipaddress.ip_network(ipaddress.IPv4Network(rule["dstAddr"]+"/"+rule["dstMask"]))):
                    dependent_switches.add(switch)

            dependent_switches = list(dependent_switches)
            dependent_switches.sort()
            if (len(dependent_switches)>1):
                lca_switch = dependent_switches[0]
                i=0
                while i<len(dependent_switches):
                    lca_switch = nx.lowest_common_ancestor(network_topology, lca_switch, dependent_switches[i])
                    i+=1
                network_subset_id = lca_switch+"+"+"-".join(dependent_switches)
                if (network_subset_id not in table_entries_subsets["networks"]):
                    table_entries_subsets["networks"][network_subset_id] = [rule]
                else:
                    table_entries_subsets["networks"][network_subset_id].append(rule)
            else:
                table_entries_subsets[dependent_switches[0]].append(rule)

    for key, subset in table_entries_subsets.items():
        if key == "networks":
            for k, sub in subset.items():
                print(k, len(sub))
                print(sub[0:5])
        else:
            print(key, len(subset))
            print(subset[0:5])

    return table_entries_subsets


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


# def bestfit_like_approach():

# def firstfit_like_approach(network_topology, switches_memory_info, table_entries_subsets):

# Determines the subset of rules for each device according to the least safe path from the inital set of nodes
# def distribute_rules(network_info, rules):
#     device_table_entries_map = {}
#     initial_nodes, not_initial_nodes = [], []

#     metric = "hops_from_source"

#     network = nx.DiGraph()
#     network.add_node("start")
#     # Separates the initial nodes and determine the subset of rules for them
#     for node, data in network_info["switches"].items():
#         network.add_node(node, **data)

#         if data[metric] == 0:
#             initial_nodes.append(node)
#             network.add_edge("start", node, weight=0)
#             end = len(rules) if data["free_table_entries"] > len(rules) else data["free_table_entries"]
#             device_table_entries_map[node] = rules[0:end]
#         else:
#             not_initial_nodes.append(node)

#     if rule_distribution_scheme == "simple":
#         for node in not_initial_nodes:
#             device_table_entries_map[node] = []
#         return device_table_entries_map

#     # Creates the edges according to the existent links
#     for link in network_info["links"]:
#         if("h" in link[0] or "h" in link[1]):
#             continue
#         network.add_edge(link[0], link[1], weight=network.nodes[link[0]]["free_table_entries"])
#         network.add_edge(link[1], link[0], weight=network.nodes[link[1]]["free_table_entries"])

#     # Calculates the least safe path length and determine the subset of rules for "node"
#     for node in not_initial_nodes:
#         l = nx.shortest_path_length(network, source="start", target=node, weight="weight")
#         end = len(rules) if network_info["switches"][node]["free_table_entries"] > len(rules) else network_info["switches"][node]["free_table_entries"]
#         device_table_entries_map[node] = rules[l: l+end]

#     return device_table_entries_map

# Parses table entires file and writes them to the corresponding switch
def write_rules(p4info_helper, switch, rules):
    for rule in rules:
        if rule["table_name"] == "ipv4_ids":
            # Remove "don't care entries" (e.g. 0.0.0.0 IP or 0-65535 port range) because P4Runtime does not accept them
            match_fields = build_match_fields(rule)
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_ids",
                priority=int(rule["priority"]),
                match_fields=match_fields,
                action_name="MyIngress."+rule["action"])
        else:
            match_fields = build_match_fields(rule, 6)
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv6_ids",
                priority=int(rule["priority"]),
                match_fields=match_fields,
                action_name="MyIngress."+rule["action"])
        switch.WriteTableEntry(table_entry)


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


def read_table_rules(p4info_helper, switch):
    print('\n----- Reading tables rules for %s -----' % switch.name)
    count = 0
    for response in switch.ReadTableEntries():
        print("Number of rules ", len(response.entities))
        for entity in response.entities:
            if(count > 5):
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


def read_counters(p4info):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info)
    for switch_id, switch in switches.items():
        print('\n----- Reading counters for %s -----' % switch.name)
        for response in switch.ReadCounters():
            print("Number of counters ", len(response.entities))
            for entity in response.entities:
                entry = entity.counter_entry
                if entry.data.packet_count > 0:
                    print('Counter name: ', p4info_helper.get_counters_name(entry.counter_id), end=' ')
                    print('\nIndex (port): ', entry.index, end=' ')
                    print("Data: ", entry.data)


def read_direct_counters(p4info, table_name):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info)
    for switch_id, switch in switches.items():
        print('\n----- Reading ipv4_ids table counters for %s -----' % switch.name)
        for response in switch.ReadDirectCounters(table_id = p4info_helper.get_tables_id(table_name)):
            print("Number of entries in direct counters ", len(response.entities))
            for entity in response.entities:
                entry = entity.direct_counter_entry
                if entry.data.packet_count > 0:
                    table_entry = entry.table_entry
                    table_name = p4info_helper.get_tables_name(table_entry.table_id)
                    print('Direct counter entry info:\n  ', table_name, end = ' ')
                    for m in table_entry.match:
                        print(p4info_helper.get_match_field_name(table_name, m.field_id), end=' ')
                        print('%r' % (p4info_helper.get_match_field_value(m),), end=' ')

                    print("\nData: ", entry.data)



def shutdown_switches():
    ShutdownAllSwitchConnections()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')

    parser.add_argument('--p4info', help='p4info proto in text format from p4c', type=str, required=False, default='../src/build/main.p4.p4info.txt')
    parser.add_argument('--bmv2_json', help='BMv2 JSON file from p4c', type=str, required=False, default='../src/build/main.json')
    parser.add_argument('--network_info', help='Network information', type=str, required=True)
    parser.add_argument('--table_entries', help='Table entries file', type=str, required=True)
    parser.add_argument('--rule_distribution_scheme', help='Distribution of rules scheme', type=str, required=True)

    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)

    install_rules(args.p4info, args.bmv2_json, args.network_info, args.table_entries, args.rule_distribution_scheme)
