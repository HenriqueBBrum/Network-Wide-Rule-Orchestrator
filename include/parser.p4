parser MyParser(packet_in packet,
                    out headers hdr,
                    inout metadata meta,
                    inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);

        meta.protocol = hdr.ethernet.etherType;
        meta.srcPort = 0;
        meta.dstPort = 0;
        meta.flags = 0;

        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV6: parse_ipv6;
            default:   accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ip.v4);
        meta.protocol = (bit<16>)hdr.ip.v4.protocol;
        transition select(hdr.ip.v4.protocol){
            TYPE_ICMP: parse_icmp;
            TYPE_TCP:  parse_tcp;
            TYPE_UDP:  parse_udp;
            default:   accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ip.v6);
        meta.protocol = (bit<16>)hdr.ip.v6.nextHeader;
        transition select(hdr.ip.v6.nextHeader){
            TYPE_ICMP: parse_icmp;
            TYPE_TCP:  parse_tcp;
            TYPE_UDP:  parse_udp;
            default:   accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.ip_encapsulated_proto.icmp);
        transition accept;
    }


    state parse_tcp {
        packet.extract(hdr.ip_encapsulated_proto.tcp);
        meta.srcPort = hdr.ip_encapsulated_proto.tcp.srcPort;
        meta.dstPort = hdr.ip_encapsulated_proto.tcp.dstPort;
        meta.flags = hdr.ip_encapsulated_proto.tcp.flags;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.ip_encapsulated_proto.udp);
        meta.srcPort = hdr.ip_encapsulated_proto.udp.srcPort;
        meta.dstPort = hdr.ip_encapsulated_proto.udp.dstPort;
        meta.flags = 0;
        transition accept;
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ip);
        packet.emit(hdr.ip_encapsulated_proto);
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}