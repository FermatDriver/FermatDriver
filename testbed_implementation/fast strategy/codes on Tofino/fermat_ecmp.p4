/* -*- P4_16 -*- */
//need to handle ARP
#include <core.p4>
#include <tna.p4>

#define PRIME 2147483647
/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
*************************************************************************/
enum bit<16> ether_type_t {
    TPID       = 0x8100,
    IPV4       = 0x0800,
    ARP        = 0x0806,
    FERMAT     = 0x88b5,
    RECOVER     = 0x88b6
}

enum bit<8>  ip_proto_t {
    ICMP  = 1,
    IGMP  = 2,
    TCP   = 6,
    UDP   = 17
}
struct ports {
    bit<16>  sp;
    bit<16>  dp;
}


type bit<48> mac_addr_t;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/
/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t    dst_addr;
    mac_addr_t    src_addr;
    ether_type_t  ether_type;
}
header tg_h
{
    bit<8> flowid;
}
header recover_h
{
    bit<32>  src_addr;
    bit<32>  dst_addr;
}
header vlan_tag_h {
    bit<3>        pcp;
    bit<1>        cfi;
    bit<12>       vid;
    ether_type_t  ether_type;
}

header arp_h {
    bit<16>       htype;
    bit<16>       ptype;
    bit<8>        hlen;
    bit<8>        plen;
    bit<16>       opcode;
    mac_addr_t    hw_src_addr;
    bit<32>       proto_src_addr;
    mac_addr_t    hw_dst_addr;
    bit<32>       proto_dst_addr;
}

header ipv4_h {
    bit<4>       version;
    bit<4>       ihl;
    bit<7>       diffserv;
    bit<1>       res;
    bit<16>      total_len;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      frag_offset;
    bit<8>       ttl;
    bit<8>   protocol;
    bit<16>      hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header icmp_h {
    bit<16>  type_code;
    bit<16>  checksum;
}

header igmp_h {
    bit<16>  type_code;
    bit<16>  checksum;
}

header tcp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<4>   res;
    bit<8>   flags;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}

header udp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<16>  len;
    bit<16>  checksum;
}

header fermat_h {
    bit<32> ip_src_addr;
    bit<32> ip_dst_addr;
    bit<2> filled;
    bit<14> index;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/
header bridge_h
{
      bit<32> ll;//indicating srcport and dstport
    bit<32> dif1;
    //bit<32> proto;
    bit<32> newid;//indicating the rest id
    bit<32> countervalue;
bit<32> dif2;
bit<32> dif3;
bit<32> dif4;
bit<32> dif5;
bit<16> indexi1;
bit<16> indexi2;
//bit<16> indexi3;

}
header outputi_h
{
    bit<32> sip01;
    bit<32> dip01;
    bit<32> ll01;
    bit<32> newid01;
    bit<32> counter01;
    bit<32> sip02;
    bit<32> dip02;
    bit<32> ll02;
    bit<32> newid02;
    bit<32> counter02;
    bit<32> sip11;
    bit<32> dip11;
    bit<32> ll11;
    bit<32> newid11;
    bit<32> counter11;
    bit<32> sip12;
    bit<32> dip12;
    bit<32> ll12;
    bit<32> newid12;
    bit<32> counter12;
}
header outpute_h
{
        bit<32> sip21;
    bit<32> dip21;
    bit<32> ll21;
    bit<32> newid21;
    bit<32> counter21;
    bit<32> sip22;
    bit<32> dip22;
    bit<32> ll22;
    bit<32> newid22;
    bit<32> counter22;
}
struct my_ingress_headers_t {
    bridge_h bridge;
    ethernet_h         ethernet;
    arp_h              arp;
    vlan_tag_h[2]      vlan_tag;
fermat_h           fermat;
    ipv4_h             ipv4;
    icmp_h             icmp;
    igmp_h             igmp;
    tcp_h              tcp;
    udp_h              udp;
    //fermat_h           fermat;	
    recover_h           rc;
    //tg_h                tg;
    outputi_h            output;
}

struct ids {
    bit<32> id1;
    bit<32> id2;
}
    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/


struct my_ingress_metadata_t {
bit<16> sp;
bit<16> dp;

bit<8> protocol;
}

struct counterid
{
    bit<32> id;
    bit<32> counter;
}
    /***********************  P A R S E R  **************************/

parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }

    state meta_init {
         hdr.bridge.setValid();
        hdr.bridge.ll     =  0;
        hdr.bridge.dif1=0;
        hdr.bridge.dif2=0;
        hdr.bridge.dif3=0;
        hdr.bridge.countervalue=0;
//        hdr.bridge.proto=0;
        hdr.bridge.newid=0;
        hdr.bridge.indexi1=0;
        hdr.bridge.indexi2=0;
        hdr.bridge.dif4=0;
        hdr.bridge.dif5=0;
        meta.sp=0;
        meta.dp=0;
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        /* 
         * The explicit cast allows us to use ternary matching on
         * serializable enum
         */        
        transition select((bit<16>)hdr.ethernet.ether_type) {
            (bit<16>)ether_type_t.TPID &&& 0xEFFF :  parse_vlan_tag;
            (bit<16>)ether_type_t.IPV4            :  parse_ipv4;
            (bit<16>)ether_type_t.ARP             :  parse_arp;
            (bit<16>)ether_type_t.FERMAT          :  parse_fermat;
            (bit<16>)ether_type_t.RECOVER          : parse_recover;
            default :  accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag.next);
        transition select(hdr.vlan_tag.last.ether_type) {
            ether_type_t.TPID :  parse_vlan_tag;
            ether_type_t.IPV4 :  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.protocol=hdr.ipv4.protocol;
        transition select(hdr.ipv4.protocol) {
            1 : parse_icmp;
            2 : parse_igmp;
            6 : parse_tcp;
           17 : parse_udp;
            default : accept;
        }
    }


    state parse_icmp {
       hdr.bridge.ll=pkt.lookahead<bit<32>>();
        pkt.extract(hdr.icmp);
        transition accept;
    }
    
    state parse_igmp {
      hdr.bridge.ll=pkt.lookahead<bit<32>>();
        pkt.extract(hdr.igmp);
        transition accept;
    }
    
    state parse_tcp {
    hdr.bridge.ll=pkt.lookahead<bit<32>>();
        pkt.extract(hdr.tcp);
        meta.sp=hdr.tcp.src_port;
        meta.dp=hdr.tcp.dst_port;
        transition accept;
    }
    
    state parse_udp {
      hdr.bridge.ll=pkt.lookahead<bit<32>>();
        pkt.extract(hdr.udp);
meta.sp=hdr.udp.src_port;
        meta.dp=hdr.udp.dst_port;
        transition accept;
    }

    state parse_fermat {
        pkt.extract(hdr.fermat);
        transition accept;
    }
/*state parse_output
{
pkt.extract(hdr.output);
transition accept;
}*/
      state parse_recover {
        pkt.extract(hdr.rc);
        transition accept;
    }


}
control Ingress(/* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{


bit<16> index1=0;
bit<16> index2=0;
bit<16> index3=0;
bit<2> errorcode=0;
bit<16> offset=0;
//bit<16> portmask=0;
bit<14> fingerprint=0;
bit<32> restid=0;
bit<8> timeflip=0;
action portmap1 ( bit<16> oft)
{
    index1=index1+oft;
    index2=index2+oft;
    //index3=index3+oft;
    restid[1:0]=errorcode;
}
@stage(3) table portmap_t1
{
key={ig_intr_md.ingress_port:exact;hdr.ipv4.res:exact;}
actions={ portmap1;}
default_action=portmap1(0);
size=8;
}



//bit<32> errorcode=0;
CRCPolynomial<bit<32>>(0x04C11DB7,false,false,false,32w0xFFFFFFFF,32w0xFFFFFFFF) crc32a;
    CRCPolynomial<bit<32>>(0x741B8CD7,false,false,false,32w0xFFFFFFFF,32w0xFFFFFFFF) crc32b;
    CRCPolynomial<bit<32>>(0xDB710641,false,false,false,32w0xFFFFFFFF,32w0xFFFFFFFF) crc32c;
CRCPolynomial<bit<32>>(0x82608EDB,false,false,false,32w0xFFFFFFFF,32w0xFFFFFFFF) crc32fp;

    Hash<bit<9>>(HashAlgorithm_t.CUSTOM,crc32a) hash_1;
    Hash<bit<9>>(HashAlgorithm_t.CUSTOM,crc32b) hash_2;
    Hash<bit<9>>(HashAlgorithm_t.CUSTOM,crc32c) hash_3;
    Hash<bit<9>>(HashAlgorithm_t.CUSTOM,crc32a) hash_i1;
    Hash<bit<9>>(HashAlgorithm_t.CUSTOM,crc32b) hash_i2;
    Hash<bit<9>>(HashAlgorithm_t.CUSTOM,crc32c) hash_i3;
    Hash<bit<3>>(HashAlgorithm_t.CUSTOM,crc32c) hash_ecmp;
    Hash<bit<14>>(HashAlgorithm_t.CUSTOM,crc32fp) hash_fp;
    Hash<bit<14>>(HashAlgorithm_t.CUSTOM,crc32fp) hash_fpi;





    Register<bit<8>, bit<2>>(0x4) timepart;
    RegisterAction<bit<8>, bit<2>, bit<8>>(timepart) work_time=
    {
void apply(inout bit<8> register_data) {
            register_data=(bit<8>)hdr.ipv4.res;

        }
    };

    Register<bit<8>, bit<2>>(0x1) timeflippart;
    RegisterAction<bit<8>, bit<2>, bit<8>>(timeflippart) work_flip=
    {
void apply(inout bit<8> register_data, out bit<8> result) {
            result=register_data;

        }
    };

action work_f ()
{
    timeflip=work_flip.execute(0);
}
@stage(0) table work_ft
{
actions={ work_f;}
default_action=work_f;
}


action work_t (bit<2> index)
{
    work_time.execute(index);
}
@stage(0) table work_tt
{
key={ig_intr_md.ingress_port:exact;}
actions={ work_t;}
default_action=work_t(0);
size=4;
}


Register<bit<32>, bit<16>>(0x02) eth_part;
    RegisterAction<bit<32>, bit<16>, bit<32>>(eth_part) work_eth=
    {
void apply(inout bit<32> register_data) {
            register_data=(bit<32>)hdr.bridge.indexi2;

        }
    };


Register<bit<32>, bit<16>>(0x02) eth_part1;
    RegisterAction<bit<32>, bit<16>, bit<32>>(eth_part1) work_eth1=
    {
void apply(inout bit<32> register_data) {
            register_data=(bit<32>)hdr.fermat.index;

        }
    };


Register<bit<32>, bit<16>>(0x1000) first_part1;
    RegisterAction<bit<32>, bit<16>, bit<32>>(first_part1) work_11=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif1)
            {
                register_data=register_data+hdr.ipv4.src_addr;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif1;
            }
            result=register_data;

        }
    };

Register<bit<32>, bit<16>>(0x1000) second_part1;
    RegisterAction<bit<32>, bit<16>, bit<32>>(second_part1) work_21=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif2)
            {
                register_data=register_data+hdr.ipv4.dst_addr;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif2;
            }
            result=register_data;
        }
    };
    
Register<bit<32>, bit<16>>(0x1000) third_part1;
    RegisterAction<bit<32>, bit<16>, bit<32>>(third_part1) work_31=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif3)
            {
                register_data=register_data+hdr.bridge.ll;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif3;
            }
            result=register_data;
        }
    };

Register<bit<32>, bit<16>>(0x1000) fourth_part1;
    RegisterAction<bit<32>, bit<16>, bit<32>>(fourth_part1) work_41=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif4)
            {
                register_data=register_data+hdr.bridge.newid;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif4;
            }
            result=register_data;
        }
    };
Register<bit<32>, bit<16>>(0x1000) counter_part1;
    RegisterAction<bit<32>, bit<16>, bit<32>>(counter_part1) work_c1=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
        if (register_data<hdr.bridge.dif5)
            {
                register_data=register_data+hdr.bridge.countervalue;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif5;
            }
            result=register_data;
        }
    };















Register<bit<32>, bit<16>>(0x1000) first_part2;
    RegisterAction<bit<32>, bit<16>, bit<32>>(first_part2) work_12=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif1)
            {
                register_data=register_data+hdr.ipv4.src_addr;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif1;
            }
            result=register_data;

        }
    };

Register<bit<32>, bit<16>>(0x1000) second_part2;
    RegisterAction<bit<32>, bit<16>, bit<32>>(second_part2) work_22=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif2)
            {
                register_data=register_data+hdr.ipv4.dst_addr;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif2;
            }
            result=register_data;
        }
    };
    
Register<bit<32>, bit<16>>(0x1000) third_part2;
    RegisterAction<bit<32>, bit<16>, bit<32>>(third_part2) work_32=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif3)
            {
                register_data=register_data+hdr.bridge.ll;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif3;
            }
            result=register_data;
        }
    };

Register<bit<32>, bit<16>>(0x1000) fourth_part2;
    RegisterAction<bit<32>, bit<16>, bit<32>>(fourth_part2) work_42=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif4)
            {
                register_data=register_data+hdr.bridge.newid;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif4;
            }
            result=register_data;
        }
    };
Register<bit<32>, bit<16>>(0x1000) counter_part2;
    RegisterAction<bit<32>, bit<16>, bit<32>>(counter_part2) work_c2=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
       if (register_data<hdr.bridge.dif5)
            {
                register_data=register_data+hdr.bridge.countervalue;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif5;
            }
            result=register_data;
        }
    };




Register<bit<32>, bit<16>>(0x1000) first_part11;
    RegisterAction<bit<32>, bit<16>, bit<32>>(first_part11) work_111=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif1)
            {
                register_data=register_data+hdr.ipv4.src_addr;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif1;
            }
            result=register_data;

        }
    };

Register<bit<32>, bit<16>>(0x1000) second_part11;
    RegisterAction<bit<32>, bit<16>, bit<32>>(second_part11) work_211=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif2)
            {
                register_data=register_data+hdr.ipv4.dst_addr;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif2;
            }
            result=register_data;
        }
    };
    
Register<bit<32>, bit<16>>(0x1000) third_part11;
    RegisterAction<bit<32>, bit<16>, bit<32>>(third_part11) work_311=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif3)
            {
                register_data=register_data+hdr.bridge.ll;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif3;
            }
            result=register_data;
        }
    };

Register<bit<32>, bit<16>>(0x1000) fourth_part11;
    RegisterAction<bit<32>, bit<16>, bit<32>>(fourth_part11) work_411=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif4)
            {
                register_data=register_data+hdr.bridge.newid;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif4;
            }
            result=register_data;
        }
    };
Register<bit<32>, bit<16>>(0x1000) counter_part11;
    RegisterAction<bit<32>, bit<16>, bit<32>>(counter_part11) work_c11=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
        if (register_data<hdr.bridge.dif5)
            {
                register_data=register_data+hdr.bridge.countervalue;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif5;
            }
            result=register_data;
        }
    };















Register<bit<32>, bit<16>>(0x1000) first_part21;
    RegisterAction<bit<32>, bit<16>, bit<32>>(first_part21) work_121=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif1)
            {
                register_data=register_data+hdr.ipv4.src_addr;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif1;
            }
            result=register_data;

        }
    };

Register<bit<32>, bit<16>>(0x1000) second_part21;
    RegisterAction<bit<32>, bit<16>, bit<32>>(second_part21) work_221=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif2)
            {
                register_data=register_data+hdr.ipv4.dst_addr;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif2;
            }
            result=register_data;
        }
    };
    
Register<bit<32>, bit<16>>(0x1000) third_part21;
    RegisterAction<bit<32>, bit<16>, bit<32>>(third_part21) work_321=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif3)
            {
                register_data=register_data+hdr.bridge.ll;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif3;
            }
            result=register_data;
        }
    };

Register<bit<32>, bit<16>>(0x1000) fourth_part21;
    RegisterAction<bit<32>, bit<16>, bit<32>>(fourth_part21) work_421=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif4)
            {
                register_data=register_data+hdr.bridge.newid;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif4;
            }
            result=register_data;
        }
    };
Register<bit<32>, bit<16>>(0x1000) counter_part21;
    RegisterAction<bit<32>, bit<16>, bit<32>>(counter_part21) work_c21=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
       if (register_data<hdr.bridge.dif5)
            {
                register_data=register_data+hdr.bridge.countervalue;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif5;
            }
            result=register_data;
        }
    };



bit<2> sip=0;
bit<2> dip=0;
bit<2> ll=0;





action calfp()//index
    {
        hdr.bridge.newid[29:16]=hash_fp.get({hdr.ipv4.src_addr,hdr.ipv4.dst_addr,hdr.bridge.ll,hdr.bridge.newid[15:0]});
    }
@stage(2)  table calfp_t
    {
        actions={calfp;}
        default_action=calfp;
    }

action calindex_layer_1()//index
    {
        index1[10:2]=hash_1.get({hdr.ipv4.src_addr,hdr.ipv4.dst_addr,hdr.bridge.ll,hdr.bridge.newid[15:0]});
    }
@stage(2)  table calindex_layer_1_t
    {
        actions={calindex_layer_1;}
        default_action=calindex_layer_1;
    }
action calindex_layer_2()//index
    {
        index2[10:2]=hash_2.get({hdr.ipv4.src_addr,hdr.ipv4.dst_addr,hdr.bridge.ll,hdr.bridge.newid[15:0]});
    }
 @stage(2)  table calindex_layer_2_t
    {
        actions={calindex_layer_2;}
        default_action=calindex_layer_2;
    }
action calindex_layer_3()//index
    {
        index3[10:2]=hash_3.get({hdr.ipv4.src_addr,hdr.ipv4.dst_addr,hdr.bridge.ll,hdr.bridge.newid[15:0]});
    }
@stage(2)  table calindex_layer_3_t
    {
        actions={calindex_layer_3;}
        default_action=calindex_layer_3;
    }


action calfpi()//index
    {
        fingerprint=hash_fpi.get({hdr.ipv4.src_addr,hdr.ipv4.dst_addr,hdr.bridge.ll,hdr.bridge.newid[15:2],errorcode});
    }
@stage(3)  table calfpi_t
    {
        actions={calfpi;}
        default_action=calfpi;
    }

action calindex_layer_i1()//index
    {
        hdr.bridge.indexi1[10:2]=hash_i1.get({hdr.ipv4.src_addr,hdr.ipv4.dst_addr,hdr.bridge.ll,hdr.bridge.newid[15:2],errorcode});
    }
@stage(3)  table calindex_layer_i1_t
    {
        actions={calindex_layer_i1;}
        default_action=calindex_layer_i1;
    }
action calindex_layer_i2()//index
    {
        hdr.bridge.indexi2[10:2]=hash_i2.get({hdr.ipv4.src_addr,hdr.ipv4.dst_addr,hdr.bridge.ll,hdr.bridge.newid[15:2],errorcode});
    }
 @stage(3)  table calindex_layer_i2_t
    {
        actions={calindex_layer_i2;}
        default_action=calindex_layer_i2;
    }
/*action calindex_layer_i3()//index
    {
        hdr.bridge.indexi3[10:2]=hash_i3.get({hdr.ipv4.src_addr,hdr.ipv4.dst_addr,hdr.bridge.ll,hdr.bridge.newid[15:2],errorcode});
    }
@stage(3)  table calindex_layer_i3_t
    {
        actions={calindex_layer_i3;}
        default_action=calindex_layer_i3;
    }*/
bit<3> ecmp=0;
action cal_ecmp()//index
    {
        ecmp=hash_ecmp.get({hdr.ipv4.src_addr,hdr.ipv4.dst_addr,hdr.bridge.ll,meta.protocol});
    }
@stage(0)  table cal_ecmp_t
    {
        actions={cal_ecmp;}
        default_action=cal_ecmp;
    }

action ecmp_select(PortId_t port)//index
    {
        ig_tm_md.ucast_egress_port=port;
    }
@stage(1)  table ecmp_select_t
    {   
        key={hdr.ipv4.dst_addr:exact;ecmp:exact;}
        actions={ecmp_select;}
        default_action=ecmp_select(0);
        size=100;
    }
action work11()
{
    hdr.output.sip01=work_11.execute(index1);
}
@stage(4) table work_t11
{
        actions={work11;}
        default_action=work11;
}

action work21()
{
    hdr.output.dip01=work_21.execute(index1);
}
@stage(4) table work_t21
{
        actions={work21;}
        default_action=work21;
}

action work31()
{
    hdr.output.ll01=work_31.execute(index1);
}
@stage(4) table work_t31
{
        actions={work31;}
        default_action=work31;
}
action work41()
{
    hdr.output.newid01=work_41.execute(index1);
}
@stage(4) table work_t41
{
        actions={work41;}
        default_action=work41;
}



 action workc1()
{
    hdr.output.counter01=work_c1.execute(index1);
}
@stage(6) table work_tc1
{
        actions={workc1;}
        default_action=workc1;
}


action work12()
{
    hdr.output.sip02=work_12.execute(index2);
}
@stage(5) table work_t12
{
        actions={work12;}
        default_action=work12;
}

action work22()
{
    hdr.output.dip02=work_22.execute(index2);
}
@stage(5) table work_t22
{
        actions={work22;}
        default_action=work22;
}

action work32()
{
    hdr.output.ll02=work_32.execute(index2);
}
@stage(5) table work_t32
{
        actions={work32;}
        default_action=work32;
}
action work42()
{
    hdr.output.newid02=work_42.execute(index2);
}
@stage(5) table work_t42
{
        actions={work42;}
        default_action=work42;
}



 action workc2()
{
    hdr.output.counter02=work_c2.execute(index2);
}
@stage(6) table work_tc2
{
        actions={workc2;}
        default_action=workc2;
}

action work111()
{
    hdr.output.sip11=work_111.execute(hdr.bridge.indexi1);
}
@stage(7) table work_t111
{
        actions={work111;}
        default_action=work111;
}

action work211()
{
    hdr.output.dip11=work_211.execute(hdr.bridge.indexi1);
}
@stage(7) table work_t211
{
        actions={work211;}
        default_action=work211;
}

action work311()
{
    hdr.output.ll11=work_311.execute(hdr.bridge.indexi1);
}
@stage(7) table work_t311
{
        actions={work311;}
        default_action=work311;
}
action work411()
{
    hdr.output.newid11=work_411.execute(hdr.bridge.indexi1);
}
@stage(7) table work_t411
{
        actions={work411;}
        default_action=work411;
}



 action workc11()
{
    hdr.output.counter11=work_c11.execute(hdr.bridge.indexi1);
}
@stage(6) table work_tc11
{
        actions={workc11;}
        default_action=workc11;
}


action work121()
{
    hdr.output.sip12=work_121.execute(hdr.bridge.indexi2);
}
@stage(8) table work_t121
{
        actions={work121;}
        default_action=work121;
}

action work221()
{
    hdr.output.dip12=work_221.execute(hdr.bridge.indexi2);
}
@stage(8) table work_t221
{
        actions={work221;}
        default_action=work221;
}

action work321()
{
    hdr.output.ll12=work_321.execute(hdr.bridge.indexi2);
}
@stage(8) table work_t321
{
        actions={work321;}
        default_action=work321;
}
action work421()
{
    hdr.output.newid12=work_421.execute(hdr.bridge.indexi2);
}
@stage(8) table work_t421
{
        actions={work421;}
        default_action=work421;
}



 action workc21()
{
    hdr.output.counter12=work_c21.execute(hdr.bridge.indexi2);
}
@stage(6) table work_tc21
{
        actions={workc21;}
        default_action=workc21;
}



 action tf(bit<16> oft)
{
  hdr.bridge.indexi1=hdr.bridge.indexi1+oft;
  hdr.bridge.indexi2=hdr.bridge.indexi2+oft;
 // hdr.bridge.indexi3=hdr.bridge.indexi3+oft;
    hdr.ipv4.res=(bit<1>)timeflip;
} 
@stage(4) table portmap_timeflip_t
{   
        key = { timeflip : exact; ig_tm_md.ucast_egress_port:exact;}
        actions={tf;}
        default_action=tf(0);
}


action match(bit<32> id)
{
    hdr.bridge.newid=id;
    restid=id;
}
@stage(1) table query_t
{
    key={sip:exact;
        dip:exact;
        ll:exact;
        meta.protocol:exact;}
    actions={match;}
    default_action=match(1);
    size=16384;
}
action diffcount()
{
        hdr.bridge.dif1=PRIME-hdr.ipv4.src_addr;
hdr.bridge.dif2=PRIME-hdr.ipv4.dst_addr;
 hdr.bridge.dif3=PRIME-hdr.bridge.ll;
hdr.bridge.dif4=PRIME-hdr.bridge.newid;
hdr.bridge.dif5=PRIME-1;
hdr.bridge.countervalue=1;

}
@stage(3) table diffcount_t
{
actions={diffcount;}
        default_action=diffcount;
}

 action settemp()
{

sip=hdr.ipv4.src_addr[31:30];
dip=hdr.ipv4.dst_addr[31:30];
ll=hdr.bridge.ll[31:30];
}
@stage(0) table st_t
{
actions = {settemp;}
default_action=settemp;
}


action settemp1()
{

hdr.ipv4.src_addr[31:30]=0;
hdr.ipv4.dst_addr[31:30]=0;
hdr.bridge.ll[31:30]=0;

}
@stage(1) table st1_t
{
actions = {settemp1;}
default_action=settemp1;
}

action settemp2()
{

hdr.bridge.newid=restid;
hdr.bridge.dif4=PRIME-restid;

}
@stage(6) table st2_t
{
actions = {settemp2;}
default_action=settemp2;
}

    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        hdr.ipv4.ttl=hdr.ipv4.ttl-1;
    }

    action drop1() {
        ig_dprsr_md.drop_ctl = 1;
        errorcode=1;
    }
    action drop2() {
        ig_dprsr_md.drop_ctl = 1;
        errorcode=errorcode+2;
    }
    action drop3() {
        ig_dprsr_md.drop_ctl = 1;
        errorcode=errorcode+1;
    }


@stage(0)  table ipv4_host {
        key = {            
            hdr.ipv4.src_addr     : ternary;
            hdr.ipv4.dst_addr     : ternary;
            meta.protocol     : ternary;
            meta.sp : ternary;
            meta.dp : ternary;}
        actions = {
            send;
        }
        const default_action =send(100);
        size = 2048;
    }
@stage(1)  table ipv4_ttl {
        actions = {
drop3;
        }
        default_action = drop3;
        size = 1;
    }




 @stage(0)  table ipv4_acl {
        key = {
            hdr.ipv4.src_addr     : ternary;
            hdr.ipv4.dst_addr     : ternary;
            hdr.ipv4.protocol     : ternary;
            meta.sp : ternary;
            meta.dp : ternary;
        }
        actions = { NoAction; drop2; }
        size    = 100;
    }
    /* The algorithm */

	




    /* arp packets processing */
    action unicast_send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.bypass_egress=1;
	//hdr.fermat.index=0xff;
         hdr.bridge.setInvalid();
    }
    action unicast_send1(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        hdr.fermat.ip_src_addr=hdr.fermat.ip_dst_addr;
	hdr.fermat.ip_dst_addr=0xC0A80109;
        hdr.fermat.filled=1;
//ig_tm_md.bypass_egress=1;
        hdr.ipv4.setValid();
	hdr.output.setValid();
        hdr.ipv4.src_addr=0;
        hdr.ipv4.dst_addr=0;
                    index1=(bit<16>)hdr.fermat.index;
            index2=(bit<16>)hdr.fermat.index;
            hdr.bridge.indexi1=(bit<16>)hdr.fermat.index;
            hdr.bridge.indexi2=(bit<16>)hdr.fermat.index;
    }
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }
    @stage(0) table arp_host {
        key = { hdr.arp.proto_dst_addr : exact; }
        actions = { unicast_send; drop; }
        default_action = drop();
    }

    /* fermat packets processing */
    @stage(0) table fermat_host {
        key = { hdr.fermat.ip_dst_addr : exact; }
        actions = { unicast_send1; unicast_send;drop; }
        default_action = drop();
    }
    @stage(0) table recover_host {
        key = { hdr.rc.dst_addr : exact; }
        actions = { unicast_send; drop; }
        default_action = drop();
    }

apply {
    if (hdr.fermat.isValid()) {
        fermat_host.apply();
    }
    
    else if (hdr.rc.isValid())
    {
        recover_host.apply();
    }
    else if (hdr.arp.isValid()) {
    arp_host.apply();
    }
    else if (hdr.ipv4.isValid())
    { 
        //sepip0_t.apply();
        cal_ecmp_t.apply();
        if (!ipv4_host.apply().hit)
        {
            ecmp_select_t.apply();
        }
        ipv4_acl.apply();
        st_t.apply();
        work_tt.apply();
        work_ft.apply();
        query_t.apply();
        if (hdr.ipv4.ttl==0)
        ipv4_ttl.apply();
        st1_t.apply();
        calindex_layer_1_t.apply();
        calindex_layer_2_t.apply();
        //calindex_layer_3_t.apply();
        calfp_t.apply();
        calfpi_t.apply();
        calindex_layer_i1_t.apply();
        calindex_layer_i2_t.apply();
        //calindex_layer_i3_t.apply();
        //calindex_layer_k_t.apply();
        portmap_t1.apply();
        portmap_timeflip_t.apply();
        diffcount_t.apply();
        //timeflip_t.apply();
    }
        if (hdr.tcp.isValid()||hdr.fermat.filled==1)
        {
        work_t11.apply();
        work_t21.apply();
        restid[29:16]=fingerprint;
        work_t31.apply();
        work_t41.apply();
        work_tc1.apply();
        work_t12.apply();
        work_t22.apply();
        
        work_t32.apply();
         work_t42.apply();
        work_tc2.apply();
        st2_t.apply();
        work_t111.apply();
        work_t211.apply();

        work_t311.apply();
        work_t411.apply();
        work_tc11.apply();
        work_t121.apply();
        work_t221.apply();

        work_t321.apply();
         work_t421.apply();
        work_tc21.apply();
        }
//hdr.bridge.setInvalid();
if (hdr.tcp.isValid())
{
   work_eth.execute(0);
}
    }

}
control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
        // Checksum() ipv4_checksum;
    
    apply {

        pkt.emit(hdr);
}
}
/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/


    struct my_egress_headers_t {
    bridge_h bridge;
    ethernet_h         ethernet;
 fermat_h           fermat;    
vlan_tag_h[2]      vlan_tag;
    ipv4_h             ipv4;
   // fermat_h            fermat;
     outpute_h          output;
}



    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {

}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition parse_hdr_bridge;
    }
    state parse_hdr_bridge {
pkt.extract(hdr.bridge);
    transition parse_ethernet;
}
    state parse_ethernet {
        pkt.extract(hdr.ethernet);    
        transition select((bit<16>)hdr.ethernet.ether_type) {
            (bit<16>)ether_type_t.TPID &&& 0xEFFF :  parse_vlan_tag;
            (bit<16>)ether_type_t.IPV4            :  parse_ipv4;
            (bit<16>)ether_type_t.FERMAT          :  parse_fermat;
            default :  accept;
        }
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag.next);
        transition select(hdr.vlan_tag.last.ether_type) {
            ether_type_t.TPID :  parse_vlan_tag;
            ether_type_t.IPV4 :  parse_ipv4;
            default: accept;
        }
    }
    state parse_fermat
    {
        pkt.extract(hdr.fermat);
        transition select(hdr.fermat.filled)
        {
            1:parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
        
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    Register<bit<32>, bit<16>>(0x02) eth_part;
    RegisterAction<bit<32>, bit<16>, bit<32>>(eth_part) work_eth=
    {
void apply(inout bit<32> register_data) {
            register_data=(bit<32>)hdr.bridge.indexi2;

        }
    };

Register<bit<32>, bit<16>>(0x1000) first_part12;
    RegisterAction<bit<32>, bit<16>, bit<32>>(first_part12) work_112=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif1)
            {
                register_data=register_data+hdr.ipv4.src_addr;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif1;
            }
            result=register_data;

        }
    };

Register<bit<32>, bit<16>>(0x1000) second_part12;
    RegisterAction<bit<32>, bit<16>, bit<32>>(second_part12) work_212=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif2)
            {
                register_data=register_data+hdr.ipv4.dst_addr;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif2;
            }
            result=register_data;
        }
    };
    
Register<bit<32>, bit<16>>(0x1000) third_part12;
    RegisterAction<bit<32>, bit<16>, bit<32>>(third_part12) work_312=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif3)
            {
                register_data=register_data+hdr.bridge.ll;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif3;
            }
            result=register_data;
        }
    };

Register<bit<32>, bit<16>>(0x1000) fourth_part12;
    RegisterAction<bit<32>, bit<16>, bit<32>>(fourth_part12) work_412=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif4)
            {
                register_data=register_data+hdr.bridge.newid;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif4;
            }
            result=register_data;
        }
    };
Register<bit<32>, bit<16>>(0x1000) counter_part12;
    RegisterAction<bit<32>, bit<16>, bit<32>>(counter_part12) work_c12=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
        if (register_data<hdr.bridge.dif5)
            {
                register_data=register_data+hdr.bridge.countervalue;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif5;
            }
            result=register_data;
        }
    };















Register<bit<32>, bit<16>>(0x1000) first_part22;
    RegisterAction<bit<32>, bit<16>, bit<32>>(first_part22) work_122=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif1)
            {
                register_data=register_data+hdr.ipv4.src_addr;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif1;
            }
            result=register_data;

        }
    };

Register<bit<32>, bit<16>>(0x1000) second_part22;
    RegisterAction<bit<32>, bit<16>, bit<32>>(second_part22) work_222=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif2)
            {
                register_data=register_data+hdr.ipv4.dst_addr;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif2;
            }
            result=register_data;
        }
    };
    
Register<bit<32>, bit<16>>(0x1000) third_part22;
    RegisterAction<bit<32>, bit<16>, bit<32>>(third_part22) work_322=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif3)
            {
                register_data=register_data+hdr.bridge.ll;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif3;
            }
            result=register_data;
        }
    };

Register<bit<32>, bit<16>>(0x1000) fourth_part22;
    RegisterAction<bit<32>, bit<16>, bit<32>>(fourth_part22) work_422=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data<hdr.bridge.dif4)
            {
                register_data=register_data+hdr.bridge.newid;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif4;
            }
            result=register_data;
        }
    };
Register<bit<32>, bit<16>>(0x1000) counter_part22;
    RegisterAction<bit<32>, bit<16>, bit<32>>(counter_part22) work_c22=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
       if (register_data<hdr.bridge.dif5)
            {
                register_data=register_data+hdr.bridge.countervalue;
            }
            else
            {
                register_data=register_data-hdr.bridge.dif5;
            }
            result=register_data;
        }
    };


action work112()
{
    hdr.output.sip21=work_112.execute(hdr.bridge.indexi1);
}
@stage(9) table work_t112
{
        actions={work112;}
        default_action=work112;
}

action work212()
{
    hdr.output.dip21=work_212.execute(hdr.bridge.indexi1);
}
@stage(9) table work_t212
{
        actions={work212;}
        default_action=work212;
}

action work312()
{
    hdr.output.ll21=work_312.execute(hdr.bridge.indexi1);
}
@stage(9) table work_t312
{
        actions={work312;}
        default_action=work312;
}
action work412()
{
    hdr.output.newid21=work_412.execute(hdr.bridge.indexi1);
}
@stage(9) table work_t412
{
        actions={work412;}
        default_action=work412;
}



 action workc12()
{
    hdr.output.counter21=work_c12.execute(hdr.bridge.indexi1);
}
@stage(11) table work_tc12
{
        actions={workc12;}
        default_action=workc12;
}


action work122()
{
    hdr.output.sip22=work_122.execute(hdr.bridge.indexi2);
}
@stage(10) table work_t122
{
        actions={work122;}
        default_action=work122;
}

action work222()
{
    hdr.output.dip22=work_222.execute(hdr.bridge.indexi2);
}
@stage(10) table work_t222
{
        actions={work222;}
        default_action=work222;
}

action work322()
{
    hdr.output.ll22=work_322.execute(hdr.bridge.indexi2);
}
@stage(10) table work_t322
{
        actions={work322;}
        default_action=work322;
}
action work422()
{
    hdr.output.newid22=work_422.execute(hdr.bridge.indexi2);
}
@stage(10) table work_t422
{
        actions={work422;}
        default_action=work422;
}



 action workc22()
{
    hdr.output.counter22=work_c22.execute(hdr.bridge.indexi2);
}
@stage(11) table work_tc22
{
        actions={workc22;}
        default_action=workc22;
}








action recover()
{
    hdr.ipv4.src_addr[31:30]=hdr.bridge.newid[15:14];
    hdr.ipv4.dst_addr[31:30]=hdr.bridge.newid[13:12];
    hdr.bridge.setInvalid();
}

@stage(11) table recover_t
{
    actions={recover;}
    default_action=recover;
}


    apply {
        if (hdr.fermat.filled==1)
        {
            hdr.output.setValid();
        }
        if (hdr.ipv4.protocol==6)
        {
	work_eth.execute(0);
	}
            if (hdr.ipv4.protocol==6||hdr.fermat.filled==1)
            {
                work_t112.apply();
                work_t212.apply();
                work_t312.apply();
                work_t412.apply();
                work_tc12.apply();
                work_t122.apply();
                work_t222.apply();
                work_t322.apply();
                work_t422.apply();
                work_tc22.apply();
            }
            
        
        recover_t.apply();
//hdr.ipv4.setInvalid();
         if (hdr.fermat.filled==1)
         {
             hdr.ipv4.setInvalid();
             hdr.fermat.filled=0;
         }
    }
}




    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{

    
     Checksum() ipv4_checksum;
    
    apply {
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.res,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });  
        }
        pkt.emit(hdr);
        
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
