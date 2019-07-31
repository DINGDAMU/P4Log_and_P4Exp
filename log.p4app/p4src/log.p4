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
        buc_val:64;
        }
}

metadata custom_metadata_t custom_metadata;
//


//==================================================






// TODO: Define the registers to store the counts
register log_register{
    width : 64;
    instance_count : 2;
}


@pragma netro reglocked log_register;









action do_read()
{

modify_field(custom_metadata.buc_sum, 127);

 modify_field(custom_metadata.buc_val, custom_metadata.buc_sum| (custom_metadata.buc_sum>> 1));
  modify_field(custom_metadata.buc_val, custom_metadata.buc_val | (custom_metadata.buc_val >> 2));
  modify_field(custom_metadata.buc_val, custom_metadata.buc_val | (custom_metadata.buc_val >> 4));
  modify_field(custom_metadata.buc_val, custom_metadata.buc_val | (custom_metadata.buc_val >> 8));
  modify_field(custom_metadata.buc_val, custom_metadata.buc_val | (custom_metadata.buc_val >> 16));
 modify_field(custom_metadata.buc_val, custom_metadata.buc_val | (custom_metadata.buc_val >> 32));


// Hamming weight is used to count the number of 1s
    modify_field(custom_metadata.buc_val, (custom_metadata.buc_val&0x5555555555555555) + ((custom_metadata.buc_val>>1)&0x5555555555555555));
    modify_field(custom_metadata.buc_val, (custom_metadata.buc_val&0x3333333333333333) + ((custom_metadata.buc_val>>2)&0x3333333333333333));
    modify_field(custom_metadata.buc_val, (custom_metadata.buc_val&0x0f0f0f0f0f0f0f0f) + ((custom_metadata.buc_val>>4)&0x0f0f0f0f0f0f0f0f));
    modify_field(custom_metadata.buc_val, (custom_metadata.buc_val&0x00ff00ff00ff00ff) + ((custom_metadata.buc_val>>8)&0x00ff00ff00ff00ff));
    modify_field(custom_metadata.buc_val, (custom_metadata.buc_val&0x0000ffff0000ffff) + ((custom_metadata.buc_val>>16)&0x0000ffff0000ffff));
    modify_field(custom_metadata.buc_val, (custom_metadata.buc_val&0x00000000ffffffff) + ((custom_metadata.buc_val>>32)&0x00000000ffffffff));

    modify_field(custom_metadata.log_value, (custom_metadata.buc_val-1)<<10);


    register_write(log_register, 0, custom_metadata.buc_sum);
    register_write(log_register, 1, custom_metadata.log_value);

}

action ipv4_forward(dstAddr, port) {
                modify_field(standard_metadata.egress_spec, port);
                modify_field(ethernet.srcAddr, ethernet.dstAddr);
                modify_field(ethernet.dstAddr, dstAddr);
                subtract_from_field(ipv4.ttl, 1);
                }


action do_log_101(){

   add_to_field(custom_metadata.log_value, 330); 
   register_write(log_register, 1, custom_metadata.log_value);
}
action do_log_110(){
   add_to_field(custom_metadata.log_value, 599); 
   register_write(log_register, 1, custom_metadata.log_value);
}
action do_log_111(){
   add_to_field(custom_metadata.log_value, 826); 
   register_write(log_register, 1, custom_metadata.log_value);
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
  
    }

control egress {
    apply(send_frame);
}
