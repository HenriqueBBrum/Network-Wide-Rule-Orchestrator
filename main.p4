#include <core.p4>
#include <v1model.p4>

#include "include/header.p4"
#include "include/parser.p4"


control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata){
    // Statistics counters
    counter(64, CounterType.packets) received;
    counter(64, CounterType.packets) redirected;
    counter(64, CounterType.packets) ids_flow;

    direct_counter(CounterType.packets_and_bytes) ipv4_ids_table_hit_counter;
    direct_counter(CounterType.packets_and_bytes) ipv6_ids_table_hit_counter;

    // Registers for the count-min sketch
    register<bit<8>>(2048) cm_limiter1;
    register<bit<8>>(2048) cm_limiter2;
    register<bit<8>>(2048) cm_limiter3;
    register<bit<8>>(2048) cm_limiter4;

    // Bit-arrays for the bloom filter
    // register<bit<2048>>(1) current_bloom_filter1;
    // register<bit<2048>>(1) current_bloom_filter2;
    // register<bit<2048>>(1) current_bloom_filter3;
    // register<bit<2048>>(1) current_bloom_filter4;

    // register<bit<2048>>(1) previous_bloom_filter1;
    // register<bit<2048>>(1) previous_bloom_filter2;
    // register<bit<2048>>(1) previous_bloom_filter3;
    // register<bit<2048>>(1) previous_bloom_filter4;


    // Variables used in IDS fowarding logic
    bit<8> current_min = 0;
    bool forward_to_ids;

    // Variables for flow expring mechanism
    bit<48> last_timestamp = 0;
    register<bit<48>>(1) timeout_aux;


    /**** Actions ****/

    action pass() {
        meta.ids_table_match = false;
        standard_metadata.egress_spec = IDS_TABLE_DEFAULT_PORT;
    }

    action redirect() {
        meta.ids_table_match = true;
        standard_metadata.egress_spec = IDS_TABLE_REDIRECT_PORT;
    }

    /**** Tables ****/

    table ipv4_ids {
        actions = {
            pass;
            redirect;
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
        counters = ipv4_ids_table_hit_counter;
    }

    table ipv6_ids{
        actions = {
            pass;
            redirect;
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
        counters = ipv6_ids_table_hit_counter;
    }

    /**** Independent actions ****/


    action get_ports(){
        if(hdr.ip_encapsulated_proto.icmp.isValid()){
            meta.srcPort = 0;
            meta.dstPort = 0;
            meta.flags = 0;
        }else if(hdr.ip_encapsulated_proto.tcp.isValid()){
            meta.srcPort = hdr.ip_encapsulated_proto.tcp.srcPort;
            meta.dstPort = hdr.ip_encapsulated_proto.tcp.dstPort;
            meta.flags = hdr.ip_encapsulated_proto.tcp.flags;
        }else if(hdr.ip_encapsulated_proto.udp.isValid()){
            meta.srcPort = hdr.ip_encapsulated_proto.udp.srcPort;
            meta.dstPort = hdr.ip_encapsulated_proto.udp.dstPort;
            meta.flags = 0;
        }
    }

    // Updates the entries for a flow in the count-min sketch if a new packet from the flow has arrived
    action increment_cm_limiter(bit<128> src_ip, bit<128> dst_ip, bit<16> src_port, bit<16> dst_port, bit<16> protocol) {
        bit<32> flow_hash1;
        bit<32> flow_hash2;
        bit<32> flow_hash3;
        bit<32> flow_hash4;

        hash(flow_hash1, HashAlgorithm.crc16, 32w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 32w2048);
        hash(flow_hash2, HashAlgorithm.csum16, 32w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 32w2048);
        hash(flow_hash3, HashAlgorithm.crc16_custom, 32w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 32w2048);
        hash(flow_hash4, HashAlgorithm.crc32, 32w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 32w2048);

        bit<8> aux_counter;

        // Update count min row 1
        cm_limiter1.read(aux_counter, (bit<32>)flow_hash1);
        log_msg("cm_limiter1 new value {}", {aux_counter + 1});
        cm_limiter1.write((bit<32>)flow_hash1, aux_counter < MAX_PACKETS ? aux_counter + 1 : MAX_PACKETS);


        // Update count min row 2
        cm_limiter2.read(aux_counter, (bit<32>)flow_hash2);
        log_msg("cm_limiter2 new value {}", {aux_counter + 1});
        cm_limiter2.write((bit<32>)flow_hash2, aux_counter < MAX_PACKETS ? aux_counter + 1 : MAX_PACKETS);


        // Update count min row 3
        cm_limiter3.read(aux_counter, (bit<32>)flow_hash3);
        log_msg("cm_limiter3 new value {}", {aux_counter + 1});
        cm_limiter3.write((bit<32>)flow_hash3, aux_counter < MAX_PACKETS ? aux_counter + 1 : MAX_PACKETS);


        // Update count min row 4
        cm_limiter4.read(aux_counter, (bit<32>)flow_hash4);
        log_msg("cm_limiter4 new value {}", {aux_counter + 1});
        cm_limiter4.write((bit<32>)flow_hash4, aux_counter < MAX_PACKETS ? aux_counter + 1 : MAX_PACKETS);
    }

    // Reads the count-min sketch and returns the min count found in all four rows
    action read_cm_limiter(bit<128> src_ip, bit<128> dst_ip, bit<16> src_port, bit<16> dst_port, bit<16> protocol) {
        bit<32> flow_hash1;
        bit<32> flow_hash2;
        bit<32> flow_hash3;
        bit<32> flow_hash4;

        hash(flow_hash1, HashAlgorithm.crc16, 32w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 32w2048);
        hash(flow_hash2, HashAlgorithm.csum16, 32w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 32w2048);
        hash(flow_hash3, HashAlgorithm.crc16_custom, 32w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 32w2048);
        hash(flow_hash4, HashAlgorithm.crc32, 32w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 32w2048);

        current_min = 0xFF;
        bit<8> aux;
        cm_limiter1.read(aux, flow_hash1);
        current_min = aux < current_min ? aux : current_min;

        cm_limiter2.read(aux, flow_hash2);
        current_min = aux < current_min ? aux : current_min;

        cm_limiter3.read(aux, flow_hash3);
        current_min = aux < current_min ? aux : current_min;

        cm_limiter4.read(aux, flow_hash4);
        current_min = aux < current_min ? aux : current_min;

        log_msg("cm_limiter minimum value {}", {current_min});
    }

    // Marks the bloom filter positions correspoding to the flow five-tuple hash. Meaning this flow is an ongoing flow
    // action track_ongoing_flows(bit<128> src_ip, bit<128> dst_ip, bit<16> src_port, bit<16> dst_port, bit<16> protocol) {
    //     bit<32> flow_hash1;
    //     bit<32> flow_hash2;
    //     bit<32> flow_hash3;
    //     bit<32> flow_hash4;

    //     hash(flow_hash1, HashAlgorithm.crc16, 32w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 32w2048);
    //     hash(flow_hash2, HashAlgorithm.csum16, 32w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 32w2048);
    //     hash(flow_hash3, HashAlgorithm.crc16_custom, 32w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 32w2048);
    //     hash(flow_hash4, HashAlgorithm.crc32, 32w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 32w2048);

    //     bit<2048> one = 1;
    //     bit<2048> aux;

    //     current_bloom_filter1.read(aux, 0);
    //     aux =  (one << flow_hash1) | aux;
    //     current_bloom_filter1.write(0, aux);

    //     current_bloom_filter2.read(aux, 0);
    //     aux =  (one << flow_hash2) | aux;
    //     current_bloom_filter2.write(0, aux);

    //     current_bloom_filter3.read(aux, 0);
    //     aux =  (one << flow_hash3) | aux;
    //     current_bloom_filter3.write(0, aux);

    //     current_bloom_filter4.read(aux, 0);
    //     aux =  (one << flow_hash4) | aux;
    //     current_bloom_filter4.write(0, aux);
    // }

    // // Removes idle entries in the bloomfliter 
    // action age_bloomfilter() {
    //     bit<2048> aux;
        
    //     current_bloom_filter1.read(aux, 0);
    //     previous_bloom_filter1.write(0, aux);
    //     current_bloom_filter1.write(0, 0);

    //     current_bloom_filter2.read(aux, 0);
    //     previous_bloom_filter2.write(0, aux);
    //     current_bloom_filter2.write(0, 0);

    //     current_bloom_filter3.read(aux, 0);
    //     previous_bloom_filter3.write(0, aux);
    //     current_bloom_filter3.write(0, 0);

    //     current_bloom_filter4.read(aux, 0);
    //     previous_bloom_filter4.write(0, aux);
    //     current_bloom_filter4.write(0, 0);

    // }

    // **** Aply block ****
    apply {
        received.count((bit<32>) standard_metadata.ingress_port);
        forward_to_ids = false;

        standard_metadata.egress_spec = IDS_TABLE_DEFAULT_PORT;

        if (hdr.ip.v4.isValid() || hdr.ip.v6.isValid()){
            bit<128> src_IP = 0;
            bit<128> dst_IP = 0;

            if (hdr.ip.v4.isValid()){
                src_IP = (bit<128>)hdr.ip.v4.srcAddr;
                dst_IP = (bit<128>)hdr.ip.v4.dstAddr;
            }else if(hdr.ip.v6.isValid()){
                src_IP = hdr.ip.v6.srcAddr;
                dst_IP = hdr.ip.v6.dstAddr;
            }

            // get_ports();
            read_cm_limiter(src_IP, dst_IP, meta.srcPort, meta.dstPort, meta.protocol);
            
            // If this flow ID is not in Count-min Sketch, meaning it is an unknown flow
            if(current_min == 0){
                // Checks if packet match an IDS rule and determines the approriate egress port
                if (hdr.ip.v4.isValid()){
                   ipv4_ids.apply();
                }else if(hdr.ip.v6.isValid()){
                   ipv6_ids.apply();
                }
                // If packet matches a rule, updates the count-min sketch and the bloom filter
                if(meta.ids_table_match){
                    ids_flow.count((bit<32>) 1);
                    forward_to_ids = true;
                }
            // This flow is already present at the Count-min Sketch but it's still needed to foward some of the flow's packets to the IDS
            }else if(current_min < MAX_PACKETS){ 
                forward_to_ids = true;
                standard_metadata.egress_spec = IDS_TABLE_REDIRECT_PORT;

            // This flow is already present at the Count-min Sketch and it's not needed to foward packets from this flow to the IDS
            }else if(current_min >= MAX_PACKETS){
                log_msg("Limit reached");
                forward_to_ids = false;
            }

            // Updates the Count-min Sketch value for this flow and updates the Bloom-fitler to account for the existence of this flow 
            if(forward_to_ids){
                increment_cm_limiter(src_IP, dst_IP, meta.srcPort, meta.dstPort, meta.protocol);
                //track_ongoing_flows(src_IP, dst_IP, meta.srcPort, meta.dstPort, meta.protocol);
            }

            // Ages the bloomfilter and zero entries that have being inactive for more than a ceratin time
            // !!!!!!!!!!!!!! Review if this code is working
            timeout_aux.read(last_timestamp, 0);
            bit<48> time_diff = standard_metadata.ingress_global_timestamp - last_timestamp;
            if (time_diff > ONE_SECOND * 10) {
                log_msg("New timeout");
                timeout_aux.write(0, standard_metadata.ingress_global_timestamp); // update
                //age_bloomfilter();
            }

            redirected.count((bit<32>) standard_metadata.egress_spec);
        }
    }
}


control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata){ 
    apply {
        
    }
}


V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
