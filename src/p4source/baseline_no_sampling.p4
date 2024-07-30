#include <core.p4>
#include <v1model.p4>

#include "include/header.p4"
#include "include/parser.p4"


control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata){
    // Statistics counters
    counter(64, CounterType.packets) received;

    /**** Apply block ****/
    apply {
        received.count((bit<32>)standard_metadata.ingress_port);
        standard_metadata.egress_spec = DEFAULT_PORT;
        clone(CloneType.I2E, REPORT_MIRROR_SESSION_ID);
    }
}


control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata){
    counter(64, CounterType.packets) cloned_to_ids;
    apply {
        cloned_to_ids.count((bit<32>) standard_metadata.egress_port);
    }
}


V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
