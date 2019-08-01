#include <core.p4>
#include <v1model.p4>

struct custom_metadata_t {
    bit<32> nhop_ipv4;
    bit<64> buc_sum;
    bit<64> buc_sumR1;
    bit<64> buc_sumR2;
    bit<32> log_value;
    bit<64> buc_val;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udplen;
    bit<16> udpchk;
}

struct metadata {
    @name(".custom_metadata") 
    custom_metadata_t custom_metadata;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".tcp") 
    tcp_t      tcp;
    @name(".udp") 
    udp_t      udp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w0x6: parse_tcp;
            8w0x11: parse_udp;
            default: accept;
        }
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    @name(".parse_udp") state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
    @name(".start") state start {
        transition parse_ethernet;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".rewrite_mac") action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    @name("._drop") action _drop() {
        mark_to_drop();
    }
    @name(".send_frame") table send_frame {
        actions = {
            rewrite_mac;
            _drop;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
    }
    apply {
        send_frame.apply();
    }
}

@name(".log_register") register<bit<64>>(32w2) log_register;

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".ipv4_forward") action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 8w1;
    }
    @name("._drop") action _drop() {
        mark_to_drop();
    }
    @name(".do_log_101") action do_log_101() {
        meta.custom_metadata.log_value = meta.custom_metadata.log_value + 32w330;
        log_register.write((bit<32>)1, (bit<64>)meta.custom_metadata.log_value);
    }
    @name(".do_log_110") action do_log_110() {
        meta.custom_metadata.log_value = meta.custom_metadata.log_value + 32w599;
        log_register.write((bit<32>)1, (bit<64>)meta.custom_metadata.log_value);
    }
    @name(".do_log_111") action do_log_111() {
        meta.custom_metadata.log_value = meta.custom_metadata.log_value + 32w826;
        log_register.write((bit<32>)1, (bit<64>)meta.custom_metadata.log_value);
    }
    @netro("reglocked", "log_register;") @name(".do_read") action do_read() {
        meta.custom_metadata.buc_sum = 64w12;
        meta.custom_metadata.buc_val = meta.custom_metadata.buc_sum | (meta.custom_metadata.buc_sum >> 1);
        meta.custom_metadata.buc_val = meta.custom_metadata.buc_val | (meta.custom_metadata.buc_val >> 2);
        meta.custom_metadata.buc_val = meta.custom_metadata.buc_val | (meta.custom_metadata.buc_val >> 4);
        meta.custom_metadata.buc_val = meta.custom_metadata.buc_val | (meta.custom_metadata.buc_val >> 8);
        meta.custom_metadata.buc_val = meta.custom_metadata.buc_val | (meta.custom_metadata.buc_val >> 16);
        meta.custom_metadata.buc_val = meta.custom_metadata.buc_val | (meta.custom_metadata.buc_val >> 32);
        meta.custom_metadata.buc_val = (meta.custom_metadata.buc_val & 64w0x5555555555555555) + ((meta.custom_metadata.buc_val >> 1) & 64w0x5555555555555555);
        meta.custom_metadata.buc_val = (meta.custom_metadata.buc_val & 64w0x3333333333333333) + ((meta.custom_metadata.buc_val >> 2) & 64w0x3333333333333333);
        meta.custom_metadata.buc_val = (meta.custom_metadata.buc_val & 64w0xf0f0f0f0f0f0f0f) + ((meta.custom_metadata.buc_val >> 4) & 64w0xf0f0f0f0f0f0f0f);
        meta.custom_metadata.buc_val = (meta.custom_metadata.buc_val & 64w0xff00ff00ff00ff) + ((meta.custom_metadata.buc_val >> 8) & 64w0xff00ff00ff00ff);
        meta.custom_metadata.buc_val = (meta.custom_metadata.buc_val & 64w0xffff0000ffff) + ((meta.custom_metadata.buc_val >> 16) & 64w0xffff0000ffff);
        meta.custom_metadata.buc_val = (meta.custom_metadata.buc_val & 64w0xffffffff) + ((meta.custom_metadata.buc_val >> 32) & 64w0xffffffff);
        meta.custom_metadata.log_value = (bit<32>)((meta.custom_metadata.buc_val - 64w1) << 10);
        log_register.write((bit<32>)0, (bit<64>)meta.custom_metadata.buc_sum);
        log_register.write((bit<32>)1, (bit<64>)meta.custom_metadata.log_value);
    }
    @name(".ipv4_lpm") table ipv4_lpm {
        actions = {
            ipv4_forward;
            _drop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
    }
    @name(".log_101") table log_101 {
        actions = {
            do_log_101;
        }
    }
    @name(".log_110") table log_110 {
        actions = {
            do_log_110;
        }
    }
    @name(".log_111") table log_111 {
        actions = {
            do_log_111;
        }
    }
    @name(".read") table read {
        actions = {
            do_read;
        }
    }
    apply {
        ipv4_lpm.apply();
        read.apply();
        meta.custom_metadata.buc_sumR1 = meta.custom_metadata.buc_sum ^ (meta.custom_metadata.buc_sum >> 8w1);
        meta.custom_metadata.buc_sumR2 = meta.custom_metadata.buc_sum ^ (meta.custom_metadata.buc_sum >> 8w2);

        if (meta.custom_metadata.buc_sum < meta.custom_metadata.buc_sumR1 ){
            if(meta.custom_metadata.buc_sum > meta.custom_metadata.buc_sumR2){
            log_101.apply();
        }
        }else {
            if (meta.custom_metadata.buc_sum < meta.custom_metadata.buc_sumR2) {
                log_110.apply();
            }
            else {
                    log_111.apply();
            }
        }
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

