# FILE RESPONSIBLE FOR SPLITTING THE NIDS RULES TO THE SWITCHES AND OFFLOADING THE TABLE ENTRIES TO THEM

import argparse
import os
import sys
import json
import networkx as nx
import matplotlib.pyplot as plt

from networkx.drawing.nx_agraph import write_dot, graphviz_layout
from time import sleep
from itertools import islice

from ipaddress import ip_address, ip_network, IPv4Network
import grpc

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections


switches = {}


def offload(p4info, bmv2_json, network_info_file, table_entries_file, offloading_algorithm):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info)
    with open(network_info_file) as f:
        network_info = json.load(f)

    with open(table_entries_file) as f:
        table_entries = f.read().splitlines()

    switches_info, hosts_info = get_network_info(network_info)
    parsed_table_entries = [get_table_entry_fields(table_entry) for table_entry in table_entries]
    ordered_table_entries = sorted(parsed_table_entries, key=lambda table_entry: table_entry['priority'], reverse=True)

    device_table_entries_map =  {switch: [] for switch in switches_info.keys()}
    if (offloading_algorithm!="firstfit" or offloading_algorithm!="bestfit"):
        device_table_entries_map["s1"] = parsed_table_entries[0:network_info["switches"]["s1"]["free_table_entries"]]
    else:
        table_entries_subsets = create_table_entries_subsets(network_info, switches_info, hosts_info, ordered_table_entries)
        device_table_entries_map = distribute_table_entries(network_info, switches_info, hosts_info, table_entries_subsets)
   
    print("\n------------------ Begin offloading -----------------------")
    try:
        # Create a switch connection object for s1 and s2; this is backed by a P4Runtime gRPC connection.
        for switch_id, table_entries in device_table_entries_map.items():
            print(switch_id, " Space: ", network_info["switches"][switch_id]["free_table_entries"], " Usage for NIDS table entries: ", len(table_entries))
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
            # Writes for each switch its table_entries
            switches[switch_id] = switch
            write_table_entries(p4info_helper, switch, table_entries)
            read_table_table_entries(p4info_helper, switch)
            print()

    except KeyboardInterrupt:
        print("Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

# Returns the information regarding what hosts are connected to what switches
def get_network_info(network_info):
    switches_info = {}
    hosts_info = {}
    switches_info = {switch: [] for switch in network_info["switches"].keys()}

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

    print("-------------------")
    print("Switches and hosts:")
    print(switches_info)
    print(hosts_info)
    print("-------------------")

    return switches_info, hosts_info

# Creates a graph and the subsets
def create_table_entries_subsets(network_info, switches_info, hosts_info, ordered_table_entries):
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

    subsets = table_entries_subsets(dag_topology, switches_info, hosts_info, ordered_table_entries)

    print("\n------------------ Table entries per switch or type -----------------------")
    for key, subset in subsets.items():
        if key == "networks":
            for k, sub in subset.items():
                print("\n------------------ Network table entries subset. Table entries key: ", k, "| Table entries length: ", len(sub), "------------------\n")
                print(sub[0:5])
        else:
            print("\n--------------- Table entries key: ", key, "| Table entries length: ", len(subset), "------------------\n")
            print(subset[0:5])

    return subsets

# Delegates the table entries to the switches according to the destination IP and the location of the hosts in the network
def table_entries_subsets(network_topology, switches_info, hosts_info, table_entries):
    table_entries_subsets = {key: [] for key in switches_info}
    table_entries_subsets["generic"] = []
    table_entries_subsets["networks"] = {}
    for table_entry in table_entries:
        try:
            if (table_entry["dstMask"]=="0.0.0.0"):
                table_entries_subsets["generic"].append(table_entry)
            elif(table_entry["dstMask"]=="255.255.255.255"):
                if (table_entry["dstAddr"]=="255.255.255.255"):
                    table_entries_subsets["generic"].append(table_entry)
                else:
                    table_entries_subsets[hosts_info[table_entry["dstAddr"]+"/24"]].append(table_entry)
            elif(table_entry["dstMask"]!="0.0.0.0" and table_entry["dstMask"]!="255.255.255.255"):
                dependent_switches = set()
                for host, switch in hosts_info.items():
                    if (ip_address(host.split("/")[0]) in ip_network(IPv4Network(table_entry["dstAddr"]+"/"+table_entry["dstMask"]))):
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
                        table_entries_subsets["networks"][network_subset_id] = [table_entry]
                    else:
                        table_entries_subsets["networks"][network_subset_id].append(table_entry)
                else:
                    table_entries_subsets[dependent_switches[0]].append(table_entry)
        except Exception as e:
            print("Error in subset: ", e.args)
    return table_entries_subsets

def distribute_table_entries(network_info, switches_info, hosts_info, table_entries_subsets):
    return {}



# Parses a table entry from the table_entry compiler list and saves the meaningful fields to a dict
def get_table_entry_fields(table_entry):
    table_entry_fields = {}
    table_entry_items = table_entry.split(" ")

    table_entry_fields["table_name"] = table_entry_items[1]
    table_entry_fields["action"] = table_entry_items[2]
    table_entry_fields["protocol"] = table_entry_items[3]

    table_entry_fields["srcAddr"] = table_entry_items[4].split("&&&")[0]
    table_entry_fields["srcMask"] = table_entry_items[4].split("&&&")[1]

    table_entry_fields["srcPortLower"] = table_entry_items[5].split("->")[0]
    table_entry_fields["srcPortUpper"] = table_entry_items[5].split("->")[1]

    table_entry_fields["dstAddr"] = table_entry_items[6].split("&&&")[0]
    table_entry_fields["dstMask"] = table_entry_items[6].split("&&&")[1]

    table_entry_fields["dstPortLower"] = table_entry_items[7].split("->")[0]
    table_entry_fields["dstPortUpper"] = table_entry_items[7].split("->")[1]

    table_entry_fields["flags"] = table_entry_items[8]

    table_entry_fields["priority"] = table_entry_items[10]

    return table_entry_fields

# Parses table entires file and writes them to the corresponding switch
def write_table_entries(p4info_helper, switch, table_entries):
    for table_entry in table_entries:
        if table_entry["table_name"] == "ipv4_ids":
            # Remove "don't care entries" (e.g. 0.0.0.0 IP or 0-65535 port range) because P4Runtime does not accept them
            match_fields = build_match_fields(table_entry)
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_ids",
                priority=int(table_entry["priority"]),
                match_fields=match_fields,
                action_name="MyIngress."+table_entry["action"])
        else:
            match_fields = build_match_fields(table_entry, 6)
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv6_ids",
                priority=int(table_entry["priority"]),
                match_fields=match_fields,
                action_name="MyIngress."+table_entry["action"])
        switch.WriteTableEntry(table_entry)

# Don't add table matches with "don't care values", including 0.0.0.0 IPs and 0->65535 port ranges
def build_match_fields(table_entry_fields, ip_version=4):
    match_fields = {}
    match_fields["meta.protocol"] = int(table_entry_fields["protocol"], base=16)
    if table_entry_fields["srcAddr"] != "0.0.0.0":
        match_fields[f"hdr.ip.v{ip_version}.srcAddr"] = (table_entry_fields["srcAddr"], table_entry_fields["srcMask"])

    if table_entry_fields["srcPortLower"] != "0" or table_entry_fields["srcPortUpper"] != "65535":
       match_fields["meta.srcPort"] = (int(table_entry_fields["srcPortLower"]), int(table_entry_fields["srcPortUpper"]))

    if table_entry_fields["dstAddr"] != "0.0.0.0":
        match_fields[f"hdr.ip.v{ip_version}.dstAddr"] = (table_entry_fields["dstAddr"], table_entry_fields["dstMask"])

    if table_entry_fields["dstPortLower"] != "0" or table_entry_fields["dstPortUpper"] != "65535":
       match_fields["meta.dstPort"] = (int(table_entry_fields["dstPortLower"]), int(table_entry_fields["dstPortUpper"]))

    match_fields["meta.flags"] = int(table_entry_fields["flags"], 2)

    return match_fields

def read_table_entries(p4info_helper, switch):
    print('\n----- Reading tables entries for %s -----' % switch.name)
    count = 0
    for response in switch.ReadTableEntries():
        print("Number of table_entries ", len(response.entities))
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
    parser.add_argument('--offloading_algorithm', help='Distribution of table entries algorithm', type=str, required=True)

    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)

    offload(args.p4info, args.bmv2_json, args.network_info, args.table_entries, args.offloading_algorithm)