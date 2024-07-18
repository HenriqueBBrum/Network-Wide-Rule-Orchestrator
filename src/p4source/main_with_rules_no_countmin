#include <core.p4>
#include <v1model.p4>

#include "include/header.p4"
#include "include/parser.p4"


control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata){
    // Statistics counters
    counter(64, CounterType.packets) received;

    direct_counter(CounterType.packets_and_bytes) ipv4_nids_table_hit_counter;
    direct_counter(CounterType.packets_and_bytes) ipv6_nids_table_hit_counter;

    /**** Actions ****/

    action pass() {
        meta.ids_table_match = false;
    }

    action clone_to_ids() {
        meta.ids_table_match = true;
    }

    /**** IDS Tables ****/

    table ipv4_nids {
        actions = {
            pass;
            clone_to_ids;
            NoAction;
        }
        key = {
           meta.protocol: exact;
           hdr.ip.v4.srcAddr: ternary;
           meta.srcPort: range;
           hdr.ip.v4.dstAddr: ternary;
           meta.dstPort: range;
           meta.flags: exact;
        }
        size = 10240;
        default_action = pass(); 
        counters = ipv4_nids_table_hit_counter;
    }

    table ipv6_nids{
        actions = {
            pass;
            clone_to_ids;
            NoAction;
        }
        key = {                
           meta.protocol: exact;
           hdr.ip.v6.srcAddr: ternary;
           meta.srcPort: range;
           hdr.ip.v6.dstAddr: ternary;
           meta.dstPort: range;
           meta.flags: exact;
        }
        size = 10240;
        default_action = pass();
        counters = ipv6_nids_table_hit_counter;
    }

    /**** Fowarding Table ****/

    action ipv4_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table ipv4_lpm {
        key = {
            hdr.ip.v4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
        }
        size = 1024;
    }

    
    /**** Apply block ****/
    apply {
        received.count((bit<32>)standard_metadata.ingress_port);
        standard_metadata.egress_spec = DEFAULT_PORT;
        if (hdr.ip.v4.isValid() || hdr.ip.v6.isValid()){
            bit<128> src_IP = 0;
            bit<128> dst_IP = 0;

            if (hdr.ip.v4.isValid()){
                //ipv4_lpm.apply();
                src_IP = (bit<128>)hdr.ip.v4.srcAddr;
                dst_IP = (bit<128>)hdr.ip.v4.dstAddr;
            }else if(hdr.ip.v6.isValid()){
                src_IP = hdr.ip.v6.srcAddr;
                dst_IP = hdr.ip.v6.dstAddr;
            }

            // Checks if packet match an IDS rule and determines the approriate egress port
            if (hdr.ip.v4.isValid()){
               ipv4_nids.apply();
            }else if(hdr.ip.v6.isValid()){
               ipv6_nids.apply();
            }

            if(meta.ids_table_match){
                clone(CloneType.I2E, REPORT_MIRROR_SESSION_ID);
            }
        }
    }
}


control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata){
    counter(64, CounterType.packets) cloned_to_ids;
    apply {
        cloned_to_ids.count((bit<32>) standard_metadata.egress_port);
    }
}


V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
