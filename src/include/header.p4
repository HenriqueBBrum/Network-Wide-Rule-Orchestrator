#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

#define REPORT_MIRROR_SESSION_ID 500 // Session for mirrored packets

const bit<48> ONE_SECOND = 1000000;

const bit<10> MAX_PACKETS=10;
const bit<48> TIME_THRESHOLD=10;
const bit<32> COUNT_MIN_SIZE=512;

const bit<9> DEFAULT_PORT = 3; // PORT TO FORWARD PACKETS
const bit<9> PORT_TO_IDS = 2; // PORT TO REDIRECT PACKETS TO SNORT


// Ethernet  EtherType field useful values
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x86DD;
const bit<16> TYPE_ALERT = 0x2345;

// IP Protocol (nextHeader) field useful values
const bit<8> TYPE_ICMP = 0x01;
const bit<8> TYPE_TCP = 0x06;
const bit<8> TYPE_UDP = 0x11;

// General typedef
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;



header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv6_t {
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowLabel;
    bit<16>   payloadLength;
    bit<8>    nextHeader;
    bit<8>    hopLImit;
    ip6Addr_t srcAddr;
    ip6Addr_t dstAddr;
}

// Header can have either IPv4 or IPv6
header_union ip_t {
  ipv4_t v4;
  ipv6_t v6;
}

header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

// Header can have UDP, TCP or ICMP
header_union ip_encapsulated_proto_t{
    udp_t  udp;
    tcp_t  tcp;
    icmp_t icmp;
}

struct ingress_metadata_t {
    bit<32> nhop_ipv4;
}

struct metadata {
    // Identifies if a clone of this packet should be sent to the IDS
    bool ids_table_match;

    //  Key fields used by the IDS_TABLE since you can have UDP, TCP and ICMP as IP encapsulation protocols
    bit<16> srcPort;
    bit<16> dstPort;
    bit<8> flags;

    bit<16> protocol;

    // !!! Removing this line causes some errors
    ingress_metadata_t   ingress_metadata;
}


struct headers {
    ethernet_t ethernet;
    ip_t    ip;
    ip_encapsulated_proto_t ip_encapsulated_proto;
}
