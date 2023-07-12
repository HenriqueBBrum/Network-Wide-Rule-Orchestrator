#include <core.p4>
#include <v1model.p4>

#include "header.p4"
#include "parser.p4"


void get_ports(inout headers hdr, inout metadata meta){
    if(hdr.ip_encap_protocol.icmp.isValid()){
        meta.srcPort = 0;
        meta.dstPort = 0;
        meta.flags = 0;
    }else if(hdr.ip_encap_protocol.tcp.isValid()){
        meta.srcPort = hdr.ip_encap_protocol.tcp.srcPort;
        meta.dstPort = hdr.ip_encap_protocol.tcp.dstPort;
        meta.flags = hdr.ip_encap_protocol.tcp.flags;
    }else if(hdr.ip_encap_protocol.udp.isValid()){
        meta.srcPort = hdr.ip_encap_protocol.udp.srcPort;
        meta.dstPort = hdr.ip_encap_protocol.udp.dstPort;
        meta.flags = 0;
    }
}


control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata){
    // Counters for stats
    counter(64, CounterType.packets) received;
    counter(64, CounterType.packets) redirected;
    counter(64, CounterType.packets) ids_flow;

    direct_counter(CounterType.packets_and_bytes) ipv4_ids_table_hit_counter;
    direct_counter(CounterType.packets_and_bytes) ipv6_ids_table_hit_counter;

    // Registers for bloom filter
    register<bit<1>>(255) bf_new_flows1;
    register<bit<1>>(255) bf_new_flows2;
    register<bit<1>>(255) bf_new_flows3;
    register<bit<1>>(255) bf_new_flows4;
    // Registers for count-min sketch
    register<bit<8>>(255) cm_limiter1;
    register<bit<8>>(255) cm_limiter2;
    register<bit<8>>(255) cm_limiter3;
    register<bit<8>>(255) cm_limiter4;

    // Variables used in ids fowarding logic
    bit<8> current_min = 0;
    bool forward_to_ids;

    // Variables for flow expring mechanism
    bit<48> last_timestamp = 0;
    register<bit<48>>(1) timeout_aux;


    /**** Tables ****/

    action pass(bit<9> port) {
        meta.ids_table_match = false;
        standard_metadata.egress_spec = port;
    }

    action redirect(bit<9> port) {
        meta.ids_table_match = true;
        standard_metadata.egress_spec = port;
    }

    table ipv4_ids {
        actions = {
            pass;
            redirect;
            NoAction;
        }
        key = {
           hdr.ip.v4.protocol: exact;
           hdr.ip.v4.srcAddr: ternary;
           meta.srcPort: range;
           hdr.ip.v4.dstAddr: ternary;
           meta.dstPort: range;
           meta.flags: ternary;
        }
        size = 10240;
        default_action = pass(PASS_PORT);
        counters = ipv4_ids_table_hit_counter;
    }


    table ipv6_ids{
        actions = {
            pass;
            redirect;
            NoAction;
        }
        key = {
           hdr.ip.v6.nextHeader: exact;
           hdr.ip.v6.srcAddr: ternary;
           meta.srcPort: range;
           hdr.ip.v6.dstAddr: ternary;
           meta.dstPort: range;
           meta.flags: ternary;
        }
        size = 10240;
        default_action = pass(PASS_PORT);
        counters = ipv6_ids_table_hit_counter;
    }

    /**** Independent actions ****/
    
    action increment_cm_limiter(bit<128> src_ip, bit<128> dst_ip, bit<16> src_port, bit<16> dst_port, bit<8> protocol) {
        bit<8> flow_hash1;
        bit<8> flow_hash2;
        bit<8> flow_hash3;
        bit<8> flow_hash4;

        hash(flow_hash1, HashAlgorithm.crc16, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);
        hash(flow_hash2, HashAlgorithm.csum16, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);
        hash(flow_hash3, HashAlgorithm.crc16_custom, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);
        hash(flow_hash4, HashAlgorithm.crc32, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);

        bit<8> aux_counter;
        cm_limiter1.read(aux_counter, (bit<32>)flow_hash1);
        // Update count min row 1
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

    action read_cm_limiter(bit<128> src_ip, bit<128> dst_ip, bit<16> src_port, bit<16> dst_port, bit<8> protocol) {
        bit<8> flow_hash1;
        bit<8> flow_hash2;
        bit<8> flow_hash3;
        bit<8> flow_hash4;
        hash(flow_hash1, HashAlgorithm.crc16, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);
        hash(flow_hash2, HashAlgorithm.csum16, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);
        hash(flow_hash3, HashAlgorithm.crc16_custom, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);
        hash(flow_hash4, HashAlgorithm.crc32, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);

        current_min = 0xFF;
        bit<8> aux;
        cm_limiter1.read(aux, (bit<32>)flow_hash1);
        current_min = aux < current_min ? aux : current_min;

        cm_limiter2.read(aux, (bit<32>)flow_hash2);
        current_min = aux < current_min ? aux : current_min;

        cm_limiter3.read(aux, (bit<32>)flow_hash3);
        current_min = aux < current_min ? aux : current_min;

        cm_limiter4.read(aux, (bit<32>)flow_hash4);
        current_min = aux < current_min ? aux : current_min;

        log_msg("cm_limiter minimum value {}", {current_min});
    }

    action track_ongoing_flows(bit<128> src_ip, bit<128> dst_ip, bit<16> src_port, bit<16> dst_port, bit<8> protocol) {
        bit<8> flow_hash1;
        bit<8> flow_hash2;
        bit<8> flow_hash3;
        bit<8> flow_hash4;

        hash(flow_hash1, HashAlgorithm.crc16, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);
        hash(flow_hash2, HashAlgorithm.csum16, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);
        hash(flow_hash3, HashAlgorithm.crc16_custom, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);
        hash(flow_hash4, HashAlgorithm.crc32, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);

        bf_new_flows1.write((bit<32>) flow_hash1, 1);
        bf_new_flows2.write((bit<32>) flow_hash2, 1);
        bf_new_flows3.write((bit<32>) flow_hash3, 1);
        bf_new_flows4.write((bit<32>) flow_hash4, 1);
    }

    // Check if this is correct
    action age_bloomfilter() {
        bit<1> has_usage;
        bit<8> current_value;
        
        bf_new_flows1.read(has_usage, 0);
        cm_limiter1.read(current_value, 0);
        cm_limiter1.write(0, has_usage == 0 ? 0 : current_value);
        bf_new_flows1.read(has_usage, 1);
        cm_limiter1.read(current_value, 1);
        cm_limiter1.write(1, has_usage == 0 ? 0 : current_value);
        bf_new_flows1.read(has_usage, 2);
        cm_limiter1.read(current_value, 2);
        cm_limiter1.write(2, has_usage == 0 ? 0 : current_value);
        bf_new_flows1.read(has_usage, 3);
        cm_limiter1.read(current_value, 3);
    }

    // **** Aply block ****
   
    apply {
        received.count((bit<32>) standard_metadata.ingress_port);
        forward_to_ids = false;

        standard_metadata.egress_spec = PASS_PORT;

        if (hdr.ip.v4.isValid() || hdr.ip.v6.isValid()){
            bit<128> src_IP = 0;
            bit<128> dst_IP = 0;
            bit<8> protocol = 0;

            if (hdr.ip.v4.isValid()){
                src_IP = (bit<128>)hdr.ip.v4.srcAddr;
                dst_IP = (bit<128>)hdr.ip.v4.dstAddr;
                protocol = hdr.ip.v4.protocol;
            }else if(hdr.ip.v6.isValid()){
                src_IP = hdr.ip.v6.srcAddr;
                dst_IP = hdr.ip.v6.dstAddr;
                protocol = hdr.ip.v6.nextHeader;
            }

            get_ports(hdr, meta);

            read_cm_limiter(src_IP, dst_IP, meta.srcPort, meta.dstPort, protocol);
            
            // if is not ids listed
            if(current_min == 0){
                // check if ids listed is needed
                if (hdr.ip.v4.isValid()){
                   ipv4_ids.apply();
                }else if(hdr.ip.v6.isValid()){
                   ipv6_ids.apply();
                }

                if(meta.ids_table_match){
                    ids_flow.count((bit<32>) 1);
                    forward_to_ids = true;
                }
            }else if(current_min < MAX_PACKETS){ // Already ids listed to be forwarded
                forward_to_ids = true;
            }else if(current_min >= MAX_PACKETS){
                log_msg("Limit reached");
                forward_to_ids = false;
            }

            if(forward_to_ids){
                increment_cm_limiter(src_IP, dst_IP, meta.srcPort, meta.dstPort, protocol);
                track_ongoing_flows(src_IP, dst_IP, meta.srcPort, meta.dstPort, protocol);
            }

            timeout_aux.read(last_timestamp, 0);
            bit<48> time_diff = standard_metadata.ingress_global_timestamp - last_timestamp;
            if (time_diff > ONE_SECOND * 10) {
                log_msg("New timeout");
                timeout_aux.write(0, standard_metadata.ingress_global_timestamp); // update
                age_bloomfilter();
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
