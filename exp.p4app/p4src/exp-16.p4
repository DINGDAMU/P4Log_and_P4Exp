#include <core.p4>
#include <v1model.p4>

struct custom_metadata_t {
    bit<32> nhop_ipv4;
    bit<64> buc_sum;
    bit<32> log_value;
    bit<64> exp_value;
    bit<64> buc_val;
    bit<32> exponent;
    bit<32> bEXP;
    bit<64> c_0;
    bit<64> c_1;
    bit<64> c_2;
    bit<64> c_3;
    bit<64> c_4;
    bit<64> c_5;
    bit<64> c_6;
    bit<64> c_7;
    bit<64> c_8;
    bit<64> c_9;
    bit<64> c_10;
    bit<64> c_11;
    bit<64> c_12;
    bit<64> c_13;
    bit<64> c_14;
    bit<64> c_15;
    bit<64> c_16;
    bit<64> c_17;
    bit<64> c_18;
    bit<64> c_19;
    bit<64> c_20;
    bit<64> c_21;
    bit<64> c_22;
    bit<64> c_23;
    bit<64> c_24;
    bit<64> c_25;
    bit<64> c_26;
    bit<64> c_27;
    bit<64> c_28;
    bit<64> c_29;
    bit<64> c_30;
    bit<64> c_31;
    bit<64> c_32;
    bit<64> c_33;
    bit<64> c_34;
    bit<64> c_35;
    bit<64> c_36;
    bit<64> c_37;
    bit<64> c_38;
    bit<64> c_39;
    bit<64> c_40;
    bit<64> c_41;
    bit<64> c_42;
    bit<64> c_43;
    bit<64> c_44;
    bit<64> c_45;
    bit<64> c_46;
    bit<64> c_47;
    bit<64> c_48;
    bit<64> c_49;
    bit<64> c_50;
    bit<64> c_51;
    bit<64> c_52;
    bit<64> c_53;
    bit<64> c_54;
    bit<64> c_55;
    bit<64> c_56;
    bit<64> c_57;
    bit<64> c_58;
    bit<64> c_59;
    bit<64> c_60;
    bit<64> c_61;
    bit<64> c_62;
    bit<64> c_63;
    bit<64> power_sum;
    bit<64> count;
    bit<64> decimal;
    bit<64> pow;
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

@name(".E_register") register<bit<64>>(32w64) E_register;

@name(".register") register<bit<64>>(32w3) register_0;

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".do_calLarge") action do_calLarge() {
        meta.custom_metadata.power_sum = (meta.custom_metadata.power_sum >> 10) * meta.custom_metadata.decimal;
        register_0.write((bit<32>)2, (bit<64>)meta.custom_metadata.power_sum);
        E_register.write((bit<32>)meta.custom_metadata.exp_value, (bit<64>)0);
    }
    @name(".do_calSmall") action do_calSmall() {
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum * meta.custom_metadata.decimal >> 10;
        register_0.write((bit<32>)2, (bit<64>)meta.custom_metadata.power_sum);
        E_register.write((bit<32>)meta.custom_metadata.exp_value, (bit<64>)0);
    }
    @name(".do_expES") action do_expES() {
        meta.custom_metadata.exponent = 32w15;
        register_0.write((bit<32>)1, (bit<64>)meta.custom_metadata.exponent);
        meta.custom_metadata.bEXP = meta.custom_metadata.exponent * meta.custom_metadata.log_value;
        meta.custom_metadata.exp_value = (bit<64>)(meta.custom_metadata.bEXP >> 10);
        meta.custom_metadata.pow = (bit<64>)meta.custom_metadata.bEXP - (meta.custom_metadata.exp_value << 10);
        meta.custom_metadata.decimal = meta.custom_metadata.decimal + meta.custom_metadata.pow;
        meta.custom_metadata.decimal = meta.custom_metadata.decimal + 64w1024;
        meta.custom_metadata.decimal = meta.custom_metadata.decimal - (meta.custom_metadata.pow * (64w1024 - meta.custom_metadata.pow) >> 11);
        meta.custom_metadata.decimal = meta.custom_metadata.decimal + (meta.custom_metadata.pow * (64w1024 - meta.custom_metadata.pow) * (64w2048 - meta.custom_metadata.pow) * 64w170 >> 30);
        E_register.read(meta.custom_metadata.count, (bit<32>)meta.custom_metadata.exp_value);
        meta.custom_metadata.count = 64w0x1;
        E_register.write((bit<32>)meta.custom_metadata.exp_value, (bit<64>)meta.custom_metadata.count);
        E_register.read(meta.custom_metadata.c_0, (bit<32>)0);
        E_register.read(meta.custom_metadata.c_1, (bit<32>)1);
        E_register.read(meta.custom_metadata.c_2, (bit<32>)2);
        E_register.read(meta.custom_metadata.c_3, (bit<32>)3);
        E_register.read(meta.custom_metadata.c_4, (bit<32>)4);
        E_register.read(meta.custom_metadata.c_5, (bit<32>)5);
        E_register.read(meta.custom_metadata.c_6, (bit<32>)6);
        E_register.read(meta.custom_metadata.c_7, (bit<32>)7);
        E_register.read(meta.custom_metadata.c_8, (bit<32>)8);
        E_register.read(meta.custom_metadata.c_9, (bit<32>)9);
        E_register.read(meta.custom_metadata.c_10, (bit<32>)10);
        E_register.read(meta.custom_metadata.c_11, (bit<32>)11);
        E_register.read(meta.custom_metadata.c_12, (bit<32>)12);
        E_register.read(meta.custom_metadata.c_13, (bit<32>)13);
        E_register.read(meta.custom_metadata.c_14, (bit<32>)14);
        E_register.read(meta.custom_metadata.c_15, (bit<32>)15);
        E_register.read(meta.custom_metadata.c_16, (bit<32>)16);
        E_register.read(meta.custom_metadata.c_17, (bit<32>)17);
        E_register.read(meta.custom_metadata.c_18, (bit<32>)18);
        E_register.read(meta.custom_metadata.c_19, (bit<32>)19);
        E_register.read(meta.custom_metadata.c_20, (bit<32>)20);
        E_register.read(meta.custom_metadata.c_21, (bit<32>)21);
        E_register.read(meta.custom_metadata.c_22, (bit<32>)22);
        E_register.read(meta.custom_metadata.c_23, (bit<32>)23);
        E_register.read(meta.custom_metadata.c_24, (bit<32>)24);
        E_register.read(meta.custom_metadata.c_25, (bit<32>)25);
        E_register.read(meta.custom_metadata.c_26, (bit<32>)26);
        E_register.read(meta.custom_metadata.c_27, (bit<32>)27);
        E_register.read(meta.custom_metadata.c_28, (bit<32>)28);
        E_register.read(meta.custom_metadata.c_29, (bit<32>)29);
        E_register.read(meta.custom_metadata.c_30, (bit<32>)30);
        E_register.read(meta.custom_metadata.c_31, (bit<32>)31);
        E_register.read(meta.custom_metadata.c_32, (bit<32>)32);
        E_register.read(meta.custom_metadata.c_33, (bit<32>)33);
        E_register.read(meta.custom_metadata.c_34, (bit<32>)34);
        E_register.read(meta.custom_metadata.c_35, (bit<32>)35);
        E_register.read(meta.custom_metadata.c_36, (bit<32>)36);
        E_register.read(meta.custom_metadata.c_37, (bit<32>)37);
        E_register.read(meta.custom_metadata.c_38, (bit<32>)38);
        E_register.read(meta.custom_metadata.c_39, (bit<32>)39);
        E_register.read(meta.custom_metadata.c_40, (bit<32>)40);
        E_register.read(meta.custom_metadata.c_41, (bit<32>)41);
        E_register.read(meta.custom_metadata.c_42, (bit<32>)42);
        E_register.read(meta.custom_metadata.c_43, (bit<32>)43);
        E_register.read(meta.custom_metadata.c_44, (bit<32>)44);
        E_register.read(meta.custom_metadata.c_45, (bit<32>)45);
        E_register.read(meta.custom_metadata.c_46, (bit<32>)46);
        E_register.read(meta.custom_metadata.c_47, (bit<32>)47);
        E_register.read(meta.custom_metadata.c_48, (bit<32>)48);
        E_register.read(meta.custom_metadata.c_49, (bit<32>)49);
        E_register.read(meta.custom_metadata.c_50, (bit<32>)50);
        E_register.read(meta.custom_metadata.c_51, (bit<32>)51);
        E_register.read(meta.custom_metadata.c_52, (bit<32>)52);
        E_register.read(meta.custom_metadata.c_53, (bit<32>)53);
        E_register.read(meta.custom_metadata.c_54, (bit<32>)54);
        E_register.read(meta.custom_metadata.c_55, (bit<32>)55);
        E_register.read(meta.custom_metadata.c_56, (bit<32>)56);
        E_register.read(meta.custom_metadata.c_57, (bit<32>)57);
        E_register.read(meta.custom_metadata.c_58, (bit<32>)58);
        E_register.read(meta.custom_metadata.c_59, (bit<32>)59);
        E_register.read(meta.custom_metadata.c_60, (bit<32>)60);
        E_register.read(meta.custom_metadata.c_61, (bit<32>)61);
        E_register.read(meta.custom_metadata.c_62, (bit<32>)62);
        E_register.read(meta.custom_metadata.c_63, (bit<32>)63);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + meta.custom_metadata.c_0 * 64w1;
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_1 * 64w1 << 1);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_2 * 64w1 << 2);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_3 * 64w1 << 3);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_4 * 64w1 << 4);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_5 * 64w1 << 5);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_6 * 64w1 << 6);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_7 * 64w1 << 7);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_8 * 64w1 << 8);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_9 * 64w1 << 9);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_10 * 64w1 << 10);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_11 * 64w1 << 11);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_12 * 64w1 << 12);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_13 * 64w1 << 13);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_14 * 64w1 << 14);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_15 * 64w1 << 15);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_16 * 64w1 << 16);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_17 * 64w1 << 17);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_18 * 64w1 << 18);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_19 * 64w1 << 19);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_20 * 64w1 << 20);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_21 * 64w1 << 21);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_22 * 64w1 << 22);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_23 * 64w1 << 23);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_24 * 64w1 << 24);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_25 * 64w1 << 25);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_26 * 64w1 << 26);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_27 * 64w1 << 27);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_28 * 64w1 << 28);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_29 * 64w1 << 29);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_30 * 64w1 << 30);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_31 * 64w1 << 31);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_32 * 64w1 << 32);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_33 * 64w1 << 33);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_34 * 64w1 << 34);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_35 * 64w1 << 35);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_36 * 64w1 << 36);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_37 * 64w1 << 37);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_38 * 64w1 << 38);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_39 * 64w1 << 39);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_40 * 64w1 << 40);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_41 * 64w1 << 41);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_42 * 64w1 << 42);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_43 * 64w1 << 43);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_44 * 64w1 << 44);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_45 * 64w1 << 45);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_46 * 64w1 << 46);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_47 * 64w1 << 47);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_48 * 64w1 << 48);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_49 * 64w1 << 49);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_50 * 64w1 << 50);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_51 * 64w1 << 51);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_52 * 64w1 << 52);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_53 * 64w1 << 53);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_54 * 64w1 << 54);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_55 * 64w1 << 55);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_56 * 64w1 << 56);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_57 * 64w1 << 57);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_58 * 64w1 << 58);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_59 * 64w1 << 59);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_60 * 64w1 << 60);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_61 * 64w1 << 61);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_62 * 64w1 << 62);
        meta.custom_metadata.power_sum = meta.custom_metadata.power_sum + (meta.custom_metadata.c_63 * 64w1 << 63);
    }
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
        register_0.write((bit<32>)1, (bit<64>)meta.custom_metadata.log_value);
    }
    @name(".do_log_110") action do_log_110() {
        meta.custom_metadata.log_value = meta.custom_metadata.log_value + 32w599;
        register_0.write((bit<32>)1, (bit<64>)meta.custom_metadata.log_value);
    }
    @name(".do_log_111") action do_log_111() {
        meta.custom_metadata.log_value = meta.custom_metadata.log_value + 32w827;
        register_0.write((bit<32>)1, (bit<64>)meta.custom_metadata.log_value);
    }
    @netro("reglocked", "register;") @netro("reglocked", "E_register;") @name(".do_read") action do_read() {
        meta.custom_metadata.buc_sum = 64w12;
        meta.custom_metadata.buc_val = meta.custom_metadata.buc_sum | meta.custom_metadata.buc_sum >> 1;
        meta.custom_metadata.buc_val = meta.custom_metadata.buc_val | meta.custom_metadata.buc_val >> 2;
        meta.custom_metadata.buc_val = meta.custom_metadata.buc_val | meta.custom_metadata.buc_val >> 4;
        meta.custom_metadata.buc_val = meta.custom_metadata.buc_val | meta.custom_metadata.buc_val >> 8;
        meta.custom_metadata.buc_val = meta.custom_metadata.buc_val | meta.custom_metadata.buc_val >> 16;
        meta.custom_metadata.buc_val = meta.custom_metadata.buc_val | meta.custom_metadata.buc_val >> 32;
        meta.custom_metadata.buc_val = (meta.custom_metadata.buc_val & 64w0x5555555555555555) + (meta.custom_metadata.buc_val >> 1 & 64w0x5555555555555555);
        meta.custom_metadata.buc_val = (meta.custom_metadata.buc_val & 64w0x3333333333333333) + (meta.custom_metadata.buc_val >> 2 & 64w0x3333333333333333);
        meta.custom_metadata.buc_val = (meta.custom_metadata.buc_val & 64w0xf0f0f0f0f0f0f0f) + (meta.custom_metadata.buc_val >> 4 & 64w0xf0f0f0f0f0f0f0f);
        meta.custom_metadata.buc_val = (meta.custom_metadata.buc_val & 64w0xff00ff00ff00ff) + (meta.custom_metadata.buc_val >> 8 & 64w0xff00ff00ff00ff);
        meta.custom_metadata.buc_val = (meta.custom_metadata.buc_val & 64w0xffff0000ffff) + (meta.custom_metadata.buc_val >> 16 & 64w0xffff0000ffff);
        meta.custom_metadata.buc_val = (meta.custom_metadata.buc_val & 64w0xffffffff) + (meta.custom_metadata.buc_val >> 32 & 64w0xffffffff);
        meta.custom_metadata.log_value = (bit<32>)(meta.custom_metadata.buc_val - 64w1 << 10);
        register_0.write((bit<32>)0, (bit<64>)meta.custom_metadata.buc_sum);
    }
    @name(".calLarge") table calLarge {
        actions = {
            do_calLarge;
        }
    }
    @name(".calSmall") table calSmall {
        actions = {
            do_calSmall;
        }
    }
    @name(".expES") table expES {
        actions = {
            do_expES;
        }
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
        if (meta.custom_metadata.buc_sum < meta.custom_metadata.buc_sum ^ meta.custom_metadata.buc_sum >> 1 && meta.custom_metadata.buc_sum > meta.custom_metadata.buc_sum ^ meta.custom_metadata.buc_sum >> 2) {
            log_101.apply();
        }
        else {
            if (meta.custom_metadata.buc_sum > meta.custom_metadata.buc_sum ^ meta.custom_metadata.buc_sum >> 1 && meta.custom_metadata.buc_sum < meta.custom_metadata.buc_sum ^ meta.custom_metadata.buc_sum >> 2) {
                log_110.apply();
            }
            else {
                if (meta.custom_metadata.buc_sum > meta.custom_metadata.buc_sum ^ meta.custom_metadata.buc_sum >> 1 && meta.custom_metadata.buc_sum > meta.custom_metadata.buc_sum ^ meta.custom_metadata.buc_sum >> 2) {
                    log_111.apply();
                }
            }
        }
        expES.apply();
        if (meta.custom_metadata.exp_value > 64w10) {
            calLarge.apply();
        }
        else {
            calSmall.apply();
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

