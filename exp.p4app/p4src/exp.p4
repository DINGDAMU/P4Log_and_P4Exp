/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS Ofactor ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "includes/headers.p4"
#include "includes/parser.p4"

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

action _drop() {
    drop();
}


//==========addtional headers========
// hash values and counts
header_type custom_metadata_t {
    fields {
        nhop_ipv4: 32;
        // TODO: Add the metadata for hash indices and count values
        buc_sum: 64;
        log_value: 32;
        exp_value: 64;
        buc_val:64;
        exponent: 32;
        bEXP: 32;
        c_0:64;
        c_1:64;
        c_2:64;
        c_3:64;
        c_4:64;
        c_5:64;
        c_6:64;
        c_7:64;
        c_8:64;
        c_9:64;
        c_10:64;
        c_11:64;
        c_12:64;
        c_13:64;
        c_14:64;
        c_15:64;
        c_16:64;
        c_17:64;
        c_18:64;
        c_19:64;
        c_20:64;
        c_21:64;
        c_22:64;
        c_23:64;
        c_24:64;
        c_25:64;
        c_26:64;
        c_27:64;
        c_28:64;
        c_29:64;
        c_30:64;
        c_31:64;
        c_32:64;
        c_33:64;
        c_34:64;
        c_35:64;
        c_36:64;
        c_37:64;
        c_38:64;
        c_39:64;
        c_40:64;
        c_41:64;
        c_42:64;
        c_43:64;
        c_44:64;
        c_45:64;
        c_46:64;
        c_47:64;
        c_48:64;
        c_49:64;
        c_50:64;
        c_51:64;
        c_52:64;
        c_53:64;
        c_54:64;
        c_55:64;
        c_56:64;
        c_57:64;
        c_58:64;
        c_59:64;
        c_60:64;
        c_61:64;
        c_62:64;
        c_63:64;
        power_sum:64;
        count:64;
        decimal:64;
        pow:64;
        }
}

metadata custom_metadata_t custom_metadata;
//


//==================================================






// TODO: Define the registers to store the counts
register register{
    width : 64;
    instance_count : 4;
}

register E_register{
    width : 64;
    instance_count : 64;
}



@pragma netro reglocked register;
@pragma netro reglocked E_register;




action do_read()
{

modify_field(custom_metadata.buc_sum, 12);

 modify_field(custom_metadata.buc_val, custom_metadata.buc_sum| (custom_metadata.buc_sum>> 1));
  modify_field(custom_metadata.buc_val, custom_metadata.buc_val | (custom_metadata.buc_val >> 2));
  modify_field(custom_metadata.buc_val, custom_metadata.buc_val | (custom_metadata.buc_val >> 4));
  modify_field(custom_metadata.buc_val, custom_metadata.buc_val | (custom_metadata.buc_val >> 8));
  modify_field(custom_metadata.buc_val, custom_metadata.buc_val | (custom_metadata.buc_val >> 16));
 modify_field(custom_metadata.buc_val, custom_metadata.buc_val | (custom_metadata.buc_val >> 32));


// Hamming weight is used to count the number of 1s
// This number is equal to the index of rightmost 1 of the hash value
    modify_field(custom_metadata.buc_val, (custom_metadata.buc_val&0x5555555555555555) + ((custom_metadata.buc_val>>1)&0x5555555555555555));
    modify_field(custom_metadata.buc_val, (custom_metadata.buc_val&0x3333333333333333) + ((custom_metadata.buc_val>>2)&0x3333333333333333));
    modify_field(custom_metadata.buc_val, (custom_metadata.buc_val&0x0f0f0f0f0f0f0f0f) + ((custom_metadata.buc_val>>4)&0x0f0f0f0f0f0f0f0f));
    modify_field(custom_metadata.buc_val, (custom_metadata.buc_val&0x00ff00ff00ff00ff) + ((custom_metadata.buc_val>>8)&0x00ff00ff00ff00ff));
    modify_field(custom_metadata.buc_val, (custom_metadata.buc_val&0x0000ffff0000ffff) + ((custom_metadata.buc_val>>16)&0x0000ffff0000ffff));
    modify_field(custom_metadata.buc_val, (custom_metadata.buc_val&0x00000000ffffffff) + ((custom_metadata.buc_val>>32)&0x00000000ffffffff));

    modify_field(custom_metadata.log_value, (custom_metadata.buc_val-1)<<10);


    register_write(register, 0, custom_metadata.buc_sum);
}

action ipv4_forward(dstAddr, port) {
                modify_field(standard_metadata.egress_spec, port);
                modify_field(ethernet.srcAddr, ethernet.dstAddr);
                modify_field(ethernet.dstAddr, dstAddr);
                subtract_from_field(ipv4.ttl, 1);
                }


action do_log_101(){

   add_to_field(custom_metadata.log_value, 330); 
   register_write(register, 1, custom_metadata.log_value);
}
action do_log_110(){
   add_to_field(custom_metadata.log_value, 599); 
   register_write(register, 1, custom_metadata.log_value);
}
action do_log_111(){
   add_to_field(custom_metadata.log_value, 827); 
   register_write(register, 1, custom_metadata.log_value);
}


action do_expES(){
    modify_field(custom_metadata.exponent, 15);

    register_write(register, 1, custom_metadata.exponent);

    modify_field(custom_metadata.bEXP, custom_metadata.exponent * custom_metadata.log_value);

   modify_field(custom_metadata.exp_value, custom_metadata.bEXP>>10); 
   modify_field(custom_metadata.pow, custom_metadata.bEXP - (custom_metadata.exp_value<<10));
   add_to_field(custom_metadata.decimal, custom_metadata.pow);
   add_to_field(custom_metadata.decimal, 1<<10);
   subtract_from_field(custom_metadata.decimal, (custom_metadata.pow * (1024 - custom_metadata.pow)) >> (10+1) );
   add_to_field(custom_metadata.decimal, (custom_metadata.pow * (1024-custom_metadata.pow)*(2048-custom_metadata.pow)*170) >> 30);
 
    register_read(custom_metadata.count, E_register, custom_metadata.exp_value);
    modify_field(custom_metadata.count, 0x01);
    register_write(E_register, custom_metadata.exp_value, custom_metadata.count);

    register_read(custom_metadata.c_0, E_register, 0);
    register_read(custom_metadata.c_1, E_register, 1);
    register_read(custom_metadata.c_2, E_register, 2);
    register_read(custom_metadata.c_3, E_register, 3);
    register_read(custom_metadata.c_4, E_register, 4);
    register_read(custom_metadata.c_5, E_register, 5);
    register_read(custom_metadata.c_6, E_register, 6);
    register_read(custom_metadata.c_7, E_register, 7);
    register_read(custom_metadata.c_8, E_register, 8);
    register_read(custom_metadata.c_9, E_register, 9);
    register_read(custom_metadata.c_10, E_register, 10);
    register_read(custom_metadata.c_11, E_register, 11);
    register_read(custom_metadata.c_12, E_register, 12);
    register_read(custom_metadata.c_13, E_register, 13);
    register_read(custom_metadata.c_14, E_register, 14);
    register_read(custom_metadata.c_15, E_register, 15);
    register_read(custom_metadata.c_16, E_register, 16);
    register_read(custom_metadata.c_17, E_register, 17);
    register_read(custom_metadata.c_18, E_register, 18);
    register_read(custom_metadata.c_19, E_register, 19);
    register_read(custom_metadata.c_20, E_register, 20);
    register_read(custom_metadata.c_21, E_register, 21);
    register_read(custom_metadata.c_22, E_register, 22);
    register_read(custom_metadata.c_23, E_register, 23);
    register_read(custom_metadata.c_24, E_register, 24);
    register_read(custom_metadata.c_25, E_register, 25);
    register_read(custom_metadata.c_26, E_register, 26);
    register_read(custom_metadata.c_27, E_register, 27);
    register_read(custom_metadata.c_28, E_register, 28);
    register_read(custom_metadata.c_29, E_register, 29);
    register_read(custom_metadata.c_30, E_register, 30);
    register_read(custom_metadata.c_31, E_register, 31);
    register_read(custom_metadata.c_32, E_register, 32);
    register_read(custom_metadata.c_33, E_register, 33);
    register_read(custom_metadata.c_34, E_register, 34);
    register_read(custom_metadata.c_35, E_register, 35);
    register_read(custom_metadata.c_36, E_register, 36);
    register_read(custom_metadata.c_37, E_register, 37);
    register_read(custom_metadata.c_38, E_register, 38);
    register_read(custom_metadata.c_39, E_register, 39);
    register_read(custom_metadata.c_40, E_register, 40);
    register_read(custom_metadata.c_41, E_register, 41);
    register_read(custom_metadata.c_42, E_register, 42);
    register_read(custom_metadata.c_43, E_register, 43);
    register_read(custom_metadata.c_44, E_register, 44);
    register_read(custom_metadata.c_45, E_register, 45);
    register_read(custom_metadata.c_46, E_register, 46);
    register_read(custom_metadata.c_47, E_register, 47);
    register_read(custom_metadata.c_48, E_register, 48);
    register_read(custom_metadata.c_49, E_register, 49);
    register_read(custom_metadata.c_50, E_register, 50);
    register_read(custom_metadata.c_51, E_register, 51);
    register_read(custom_metadata.c_52, E_register, 52);
    register_read(custom_metadata.c_53, E_register, 53);
    register_read(custom_metadata.c_54, E_register, 54);
    register_read(custom_metadata.c_55, E_register, 55);
    register_read(custom_metadata.c_56, E_register, 56);
    register_read(custom_metadata.c_57, E_register, 57);
    register_read(custom_metadata.c_58, E_register, 58);
    register_read(custom_metadata.c_59, E_register, 59);
    register_read(custom_metadata.c_60, E_register, 60);
    register_read(custom_metadata.c_61, E_register, 61);
    register_read(custom_metadata.c_62, E_register, 62);
    register_read(custom_metadata.c_63, E_register, 63);
    
    add_to_field(custom_metadata.power_sum, custom_metadata.c_0 * 1);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_1 * 1<<1);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_2 * 1<<2);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_3 * 1<<3);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_4 * 1<<4);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_5 * 1<<5);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_6 * 1<<6);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_7 * 1<<7);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_8 * 1<<8);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_9 * 1<<9);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_10 * 1<<10);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_11 * 1<<11);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_12 * 1<<12);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_13 * 1<<13);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_14 * 1<<14);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_15 * 1<<15);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_16 * 1<<16);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_17 * 1<<17);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_18 * 1<<18);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_19 * 1<<19);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_20 * 1<<20);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_21 * 1<<21);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_22 * 1<<22);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_23 * 1<<23);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_24 * 1<<24);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_25 * 1<<25);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_26 * 1<<26);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_27 * 1<<27);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_28 * 1<<28);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_29 * 1<<29);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_30 * 1<<30);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_31 * 1<<31);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_32 * 1<<32);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_33 * 1<<33);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_34 * 1<<34);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_35 * 1<<35);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_36 * 1<<36);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_37 * 1<<37);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_38 * 1<<38);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_39 * 1<<39);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_40 * 1<<40);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_41 * 1<<41);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_42 * 1<<42);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_43 * 1<<43);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_44 * 1<<44);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_45 * 1<<45);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_46 * 1<<46);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_47 * 1<<47);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_48 * 1<<48);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_49 * 1<<49);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_50 * 1<<50);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_51 * 1<<51);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_52 * 1<<52);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_53 * 1<<53);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_54 * 1<<54);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_55 * 1<<55);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_56 * 1<<56);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_57 * 1<<57);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_58 * 1<<58);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_59 * 1<<59);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_60 * 1<<60);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_61 * 1<<61);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_62 * 1<<62);
    add_to_field(custom_metadata.power_sum, custom_metadata.c_63 * 1<<63);

   }

action do_calLarge(){

    modify_field(custom_metadata.power_sum, (custom_metadata.power_sum>>10) * custom_metadata.decimal);

    register_write(register, 2, custom_metadata.power_sum);
    register_write(E_register, custom_metadata.exp_value, 0);

}

action do_calSmall(){
    modify_field(custom_metadata.power_sum, (custom_metadata.power_sum * custom_metadata.decimal)>>10);

    register_write(register, 2, custom_metadata.power_sum);
    register_write(E_register, custom_metadata.exp_value, 0);

}
// TODO: Define the tables to run actions




//
table ipv4_lpm{
    reads{
        ipv4.dstAddr : lpm;
        }
    actions{
        ipv4_forward;
        _drop;
        }
    size: 1024;
    }
//
//==========================================================================================================
//Time collection
//==========================================================================================================
action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    size: 256;
}

table read{
    actions {
        do_read;
        }
}



table log_101 {
    actions {
        do_log_101;
    }
}
table log_110 {
    actions {
        do_log_110;
    }
}
table log_111 {
    actions {
        do_log_111;
    }
}


table expES{
    actions{
        do_expES;
        }

}
table calLarge{
    actions{
        do_calLarge;
        }

}
table calSmall{
    actions{
        do_calSmall;
        }

}

control ingress {

    apply(ipv4_lpm);
    apply(read);
if(custom_metadata.buc_sum < custom_metadata.buc_sum ^ (custom_metadata.buc_sum >> 1) && custom_metadata.buc_sum > custom_metadata.buc_sum ^ (custom_metadata.buc_sum >> 2)  ){
            apply(log_101);
        }else if (custom_metadata.buc_sum > custom_metadata.buc_sum ^ (custom_metadata.buc_sum >> 1) && custom_metadata.buc_sum < custom_metadata.buc_sum ^ (custom_metadata.buc_sum >> 2)  ){
            apply(log_110);
        }else if (custom_metadata.buc_sum > custom_metadata.buc_sum ^ (custom_metadata.buc_sum >> 1) && custom_metadata.buc_sum > custom_metadata.buc_sum ^ (custom_metadata.buc_sum >> 2)  ){
            apply(log_111);
          }    
    apply(expES);
    if (custom_metadata.exp_value > 10){
        apply(calLarge);
    }else{
        apply(calSmall);
    }

}

control egress {
    apply(send_frame);
}
