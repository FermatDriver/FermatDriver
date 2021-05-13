#include <bf_rt/bf_rt_info.hpp>
#include <bf_rt/bf_rt_init.hpp>
#include <bf_rt/bf_rt_common.h>
#include <bf_rt/bf_rt_table_key.hpp>
#include <bf_rt/bf_rt_table_data.hpp>
#include <bf_rt/bf_rt_table_operations.hpp>
#include <bf_rt/bf_rt_table.hpp>
#include <getopt.h>
#include<sys/time.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include<vector>
#include <arpa/inet.h>
extern "C"
{
#include <bf_pm/bf_pm_intf.h>
#include <pkt_mgr/pkt_mgr_intf.h>
#include <bf_switchd/bf_switchd.h>
}

FILE *logs = fopen("logs", "w");

uint64_t expected_time;
//uint32_t ruleexists[9][9][256];
uint32_t recoverflag;
#define carry_num 2048
#define switch_id 0
#define counter_num 16384
struct __attribute__((__packed__)) recoverFlow
{
  uint32_t ipsrc;
  uint32_t ipdst;
  uint8_t protocol;
  uint16_t  sport;
  uint16_t dport;
  uint16_t dst_switch_port;
};

struct __attribute__((__packed__)) recover_header
{
  uint8_t ethdstAddr[6];
  uint8_t ethsrcAddr[6];
  uint16_t ethtype;
  uint32_t ipsrcAddr;
  uint32_t ipdstAddr;
  uint16_t recovery_mode;//0 route table,1 ecmp
  uint16_t loss_num;
  struct recoverFlow rF[carry_num/16];
};

struct rule
{
  uint32_t srcip;
  uint32_t srcip_mask;
  uint32_t dstip;
  uint32_t dstip_mask;
  uint8_t protocol;
  uint16_t srcport;
  uint16_t srcport_mask;
  uint16_t dstport;
  uint16_t dstport_mask;
  uint32_t priority;
  uint32_t nexthop;

};



typedef struct __attribute__((__packed__)) tcp_t {
  uint8_t ethdstAddr[6];
  uint8_t ethsrcAddr[6];
  uint16_t ethtype;
  uint32_t ipsrcAddr;
  uint32_t ipdstAddr;
  uint16_t linkid;
  uint8_t arrayid; //(src,dst, sdport,rest,counter)
  uint8_t componentid;
  uint32_t switchid;
  uint32_t up_or_down;//up=1 down=0;
  uint32_t timeflag;
  uint32_t payload[carry_num];
} tcp;




uint32_t array[2][250000]; //0-8191 first11-0 second11-0 
uint32_t array1[2][250000];
uint32_t array2[2][250000]; //0-8191 first11-0 second11-0 
#define ALL_PIPES 0xffff
#define Ingress_port_num 4
uint32_t tf[2][Ingress_port_num*2];
//uint16_t linkmap[4][3]={{9,1,1},{13,2,2},{17,3,3},{21,4,4}};// switch 1
//uint16_t linkmap[4][3]={{10,5,5},{14,6,6},{18,7,7},{22,8,8}};// switch 2
//uint16_t linkmap[4][3]={{1,9,9},{5,10,10},{27,11,11},{31,12,12}};// switch 3
//uint16_t linkmap[4][3]={{2,13,13},{6,14,14},{28,15,15},{32,16,16}};// switch 4
//uint16_t linkmap[4][3]={{3,17,17},{7,18,18},{35,19,19},{39,20,20}};// switch 5
//uint16_t linkmap[4][3]={{4,21,21},{8,22,22},{36,23,23},{40,24,24}};// switch 6
//uint16_t linkmap[4][3]={{0,25,25},{0,26,26},{11,27,27},{15,28,28}};// switch 7
//uint16_t linkmap[4][3]={{0,29,29},{0,30,30},{12,31,31},{16,32,32}};// switch 8
//uint16_t linkmap[4][3]={{0,33,33},{0,34,34},{19,35,35},{23,36,36}};// switch 9
uint16_t linkmap[4][3]={{0,37,37},{0,38,38},{20,39,39},{24,40,40}};// switch 10
// portmap[2]={}
size_t tcp_pkt_sz = sizeof(tcp); // 1500 byte pkt
bf_pkt_tx_ring_t tx_ring1 = BF_PKT_TX_RING_0;
void generate_and_send (uint32_t index, uint32_t timeflag,uint32_t uod, uint32_t* ary) {
  bf_pkt *bftcppkt = NULL;
  tcp tcp_pkt;
  if (bf_pkt_alloc(0, &bftcppkt, tcp_pkt_sz, BF_DMA_CPU_PKT_TRANSMIT_0) != 0) {
    printf("Failed bf_pkt_alloc\n");
  }
  uint8_t dstAddr[] = {0x3c, 0xfd, 0xfe, 0xad, 0x82, 0xe0};//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4};// {0xf4, 0xe7, 0xb7, 0xfe, 0xfd, 0x3c};
  uint8_t srcAddr[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x11};
  memcpy(tcp_pkt.ethdstAddr, dstAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
  memcpy(tcp_pkt.ethsrcAddr, srcAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
  tcp_pkt.ethtype=htons(0x88b5);
  tcp_pkt.ipdstAddr = htonl(0xC0A80109);
  tcp_pkt.ipsrcAddr = htonl(0x0a000002);
  tcp_pkt.switchid = switch_id;
  uint32_t pid=(index/carry_num)%4;
  tcp_pkt.arrayid=((index*2)/counter_num/5)%3;
  tcp_pkt.componentid=((index*2)/counter_num)%5;


  tcp_pkt.linkid=linkmap[pid][uod];
  tcp_pkt.up_or_down=uod;
  tcp_pkt.timeflag = timeflag;
  uint8_t * tpkt = (uint8_t *) malloc(tcp_pkt_sz);
  memcpy(tpkt, &tcp_pkt, tcp_pkt_sz);
  memcpy(tpkt+tcp_pkt_sz-carry_num*4, ary+index, carry_num*4);
  if (bf_pkt_data_copy(bftcppkt, tpkt, tcp_pkt_sz) != 0) {
    printf("Failed data copy\n");
  }

  bf_status_t stat = bf_pkt_tx(0, bftcppkt, tx_ring1, (void *)bftcppkt);
  if (stat  != BF_SUCCESS) 
  {
    printf("Failed to send packet status=%s\n", bf_err_str(stat));
    bf_pkt_free(0,bftcppkt);
  }
  //else std::cout<<"sent"<<uod<<std::endl;
  
}


void generate_packets_for_upstream(uint32_t timeflag)
{
  for (uint32_t i=0;i<counter_num/2*15/carry_num;i++)
  generate_and_send(i*carry_num,timeflag,1,array[timeflag]);
}
void generate_packets_for_midstream(uint32_t timeflag)
{
  for (uint32_t i=0;i<counter_num/2*15/carry_num;i++)
  generate_and_send(i*carry_num,timeflag,2,array2[timeflag]);
}

void generate_packets_for_downstream(uint32_t timeflag)
{
  for (uint32_t i=0;i<counter_num/2*15/carry_num;i++)
  {
    generate_and_send(i*carry_num,timeflag,0,array1[timeflag]);
  }
}
void generate_packets(uint32_t timeflag)
{
  generate_packets_for_upstream(timeflag);
  generate_packets_for_midstream(timeflag);
  generate_packets_for_downstream(timeflag);
}
std::unique_ptr<bfrt::BfRtTableKey> bfrtTableKey;
std::unique_ptr<bfrt::BfRtTableData> bfrtTableData;
const bfrt::BfRtTable *ipv4_host_table=nullptr;
bf_rt_id_t srcip_field_id = 0;
bf_rt_id_t dstip_field_id = 0;
bf_rt_id_t proto_field_id = 0;
bf_rt_id_t sp_field_id = 0;
bf_rt_id_t dp_field_id = 0;
bf_rt_id_t ipv4_host_send_action_id = 0;
bf_rt_id_t send_port_field_id = 0;
bf_rt_id_t match_field_id = 0;

std::vector<std::unique_ptr<bfrt::BfRtTableKey>> timeflippart_key(1);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> timeflippart_data(1);
const bfrt::BfRtTable *timeflippart_table=nullptr;
bf_rt_id_t timeflippart_data_id=0;


uint64_t flag=0;
std::vector<std::unique_ptr<bfrt::BfRtTableKey>> timepart_key(Ingress_port_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> timepart_data(Ingress_port_num);
const bfrt::BfRtTable *timepart_table=nullptr;
bf_rt_id_t timepart_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> timepart_to1 = nullptr;



std::vector<std::unique_ptr<bfrt::BfRtTableKey>> first_part11_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> first_part11_data(counter_num);
const bfrt::BfRtTable *first_part11_table=nullptr;
bf_rt_id_t first_part11_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> first_part11_to = nullptr;
std::unique_ptr<bfrt::BfRtTableOperations> first_part1_to1 = nullptr;

std::vector<std::unique_ptr<bfrt::BfRtTableKey>> second_part11_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> second_part11_data(counter_num);
const bfrt::BfRtTable *second_part11_table=nullptr;
bf_rt_id_t second_part11_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> second_part11_to = nullptr;
std::unique_ptr<bfrt::BfRtTableOperations> second_part1_to1 = nullptr;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> third_part11_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> third_part11_data(counter_num);
const bfrt::BfRtTable *third_part11_table=nullptr;
bf_rt_id_t third_part11_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> third_part11_to = nullptr;
std::unique_ptr<bfrt::BfRtTableOperations> third_part1_to1 = nullptr;

std::vector<std::unique_ptr<bfrt::BfRtTableKey>> counter_part11_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> counter_part11_data(counter_num);
const bfrt::BfRtTable *counter_part11_table=nullptr;
bf_rt_id_t counter_part11_data_id=0;
bf_rt_id_t counter_part11_data_id2=0;
std::unique_ptr<bfrt::BfRtTableOperations> counter_part11_to = nullptr;
std::unique_ptr<bfrt::BfRtTableOperations> counter_part1_to1 = nullptr;

std::vector<std::unique_ptr<bfrt::BfRtTableKey>> first_part21_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> first_part21_data(counter_num);
const bfrt::BfRtTable *first_part21_table=nullptr;
bf_rt_id_t first_part21_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> first_part21_to = nullptr;
std::unique_ptr<bfrt::BfRtTableOperations> first_part2_to1 = nullptr;

std::vector<std::unique_ptr<bfrt::BfRtTableKey>> second_part21_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> second_part21_data(counter_num);
const bfrt::BfRtTable *second_part21_table=nullptr;
bf_rt_id_t second_part21_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> second_part21_to = nullptr;
std::unique_ptr<bfrt::BfRtTableOperations> second_part2_to1 = nullptr;

std::vector<std::unique_ptr<bfrt::BfRtTableKey>> third_part21_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> third_part21_data(counter_num);
const bfrt::BfRtTable *third_part21_table=nullptr;
bf_rt_id_t third_part21_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> third_part21_to = nullptr;
std::unique_ptr<bfrt::BfRtTableOperations> third_part2_to1 = nullptr;

std::vector<std::unique_ptr<bfrt::BfRtTableKey>> counter_part21_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> counter_part21_data(counter_num);
const bfrt::BfRtTable *counter_part21_table=nullptr;
bf_rt_id_t counter_part21_data_id=0;
bf_rt_id_t counter_part21_data_id2=0;
std::unique_ptr<bfrt::BfRtTableOperations> counter_part21_to = nullptr;
std::unique_ptr<bfrt::BfRtTableOperations> counter_part2_to1 = nullptr;

std::vector<std::unique_ptr<bfrt::BfRtTableKey>> first_part31_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> first_part31_data(counter_num);
const bfrt::BfRtTable *first_part31_table=nullptr;
bf_rt_id_t first_part31_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> first_part31_to = nullptr;
std::unique_ptr<bfrt::BfRtTableOperations> first_part3_to1 = nullptr;

std::vector<std::unique_ptr<bfrt::BfRtTableKey>> second_part31_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> second_part31_data(counter_num);
const bfrt::BfRtTable *second_part31_table=nullptr;
bf_rt_id_t second_part31_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> second_part31_to = nullptr;
std::unique_ptr<bfrt::BfRtTableOperations> second_part3_to1 = nullptr;

std::vector<std::unique_ptr<bfrt::BfRtTableKey>> third_part31_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> third_part31_data(counter_num);
const bfrt::BfRtTable *third_part31_table=nullptr;
bf_rt_id_t third_part31_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> third_part31_to = nullptr;
std::unique_ptr<bfrt::BfRtTableOperations> third_part3_to1 = nullptr;

std::vector<std::unique_ptr<bfrt::BfRtTableKey>> counter_part31_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> counter_part31_data(counter_num);
const bfrt::BfRtTable *counter_part31_table=nullptr;
bf_rt_id_t counter_part31_data_id=0;
bf_rt_id_t counter_part31_data_id2=0;
std::unique_ptr<bfrt::BfRtTableOperations> counter_part31_to = nullptr;
std::unique_ptr<bfrt::BfRtTableOperations> counter_part3_to1 = nullptr;

std::vector<std::unique_ptr<bfrt::BfRtTableKey>> first_part12_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> first_part12_data(counter_num);
const bfrt::BfRtTable *first_part12_table=nullptr;
bf_rt_id_t first_part12_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> first_part12_to = nullptr;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> second_part12_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> second_part12_data(counter_num);
const bfrt::BfRtTable *second_part12_table=nullptr;
bf_rt_id_t second_part12_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> second_part12_to = nullptr;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> third_part12_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> third_part12_data(counter_num);
const bfrt::BfRtTable *third_part12_table=nullptr;
bf_rt_id_t third_part12_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> third_part12_to = nullptr;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> counter_part12_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> counter_part12_data(counter_num);
const bfrt::BfRtTable *counter_part12_table=nullptr;
bf_rt_id_t counter_part12_data_id=0;
bf_rt_id_t counter_part12_data_id2=0;
std::unique_ptr<bfrt::BfRtTableOperations> counter_part12_to = nullptr;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> first_part22_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> first_part22_data(counter_num);
const bfrt::BfRtTable *first_part22_table=nullptr;
bf_rt_id_t first_part22_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> first_part22_to = nullptr;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> second_part22_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> second_part22_data(counter_num);
const bfrt::BfRtTable *second_part22_table=nullptr;
bf_rt_id_t second_part22_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> second_part22_to = nullptr;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> third_part22_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> third_part22_data(counter_num);
const bfrt::BfRtTable *third_part22_table=nullptr;
bf_rt_id_t third_part22_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> third_part22_to = nullptr;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> counter_part22_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> counter_part22_data(counter_num);
const bfrt::BfRtTable *counter_part22_table=nullptr;
bf_rt_id_t counter_part22_data_id=0;
bf_rt_id_t counter_part22_data_id2=0;
std::unique_ptr<bfrt::BfRtTableOperations> counter_part22_to = nullptr;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> first_part32_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> first_part32_data(counter_num);
const bfrt::BfRtTable *first_part32_table=nullptr;
bf_rt_id_t first_part32_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> first_part32_to = nullptr;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> second_part32_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> second_part32_data(counter_num);
const bfrt::BfRtTable *second_part32_table=nullptr;
bf_rt_id_t second_part32_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> second_part32_to = nullptr;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> third_part32_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> third_part32_data(counter_num);
const bfrt::BfRtTable *third_part32_table=nullptr;
bf_rt_id_t third_part32_data_id=0;
std::unique_ptr<bfrt::BfRtTableOperations> third_part32_to = nullptr;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> counter_part32_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> counter_part32_data(counter_num);
const bfrt::BfRtTable *counter_part32_table=nullptr;
bf_rt_id_t counter_part32_data_id=0;
bf_rt_id_t counter_part32_data_id2=0;
std::unique_ptr<bfrt::BfRtTableOperations> counter_part32_to = nullptr;




std::vector<std::unique_ptr<bfrt::BfRtTableKey>> first_part1_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> first_part1_data(counter_num);
const bfrt::BfRtTable *first_part1_table=nullptr;
bf_rt_id_t first_part1_data_id=0;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> second_part1_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> second_part1_data(counter_num);
const bfrt::BfRtTable *second_part1_table=nullptr;
bf_rt_id_t second_part1_data_id=0;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> third_part1_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> third_part1_data(counter_num);
const bfrt::BfRtTable *third_part1_table=nullptr;
bf_rt_id_t third_part1_data_id=0;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> counter_part1_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> counter_part1_data(counter_num);
const bfrt::BfRtTable *counter_part1_table=nullptr;
bf_rt_id_t counter_part1_data_id=0;
bf_rt_id_t counter_part1_data_id2=0;



std::vector<std::unique_ptr<bfrt::BfRtTableKey>> first_part2_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> first_part2_data(counter_num);
const bfrt::BfRtTable *first_part2_table=nullptr;
bf_rt_id_t first_part2_data_id=0;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> second_part2_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> second_part2_data(counter_num);
const bfrt::BfRtTable *second_part2_table=nullptr;
bf_rt_id_t second_part2_data_id=0;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> third_part2_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> third_part2_data(counter_num);
const bfrt::BfRtTable *third_part2_table=nullptr;
bf_rt_id_t third_part2_data_id=0;

std::vector<std::unique_ptr<bfrt::BfRtTableKey>> counter_part2_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> counter_part2_data(counter_num);
const bfrt::BfRtTable *counter_part2_table=nullptr;
bf_rt_id_t counter_part2_data_id=0;
bf_rt_id_t counter_part2_data_id2=0;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> first_part3_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> first_part3_data(counter_num);
const bfrt::BfRtTable *first_part3_table=nullptr;
bf_rt_id_t first_part3_data_id=0;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> second_part3_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> second_part3_data(counter_num);
const bfrt::BfRtTable *second_part3_table=nullptr;
bf_rt_id_t second_part3_data_id=0;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> third_part3_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> third_part3_data(counter_num);
const bfrt::BfRtTable *third_part3_table=nullptr;
bf_rt_id_t third_part3_data_id=0;


std::vector<std::unique_ptr<bfrt::BfRtTableKey>> counter_part3_key(counter_num);
std::vector<std::unique_ptr<bfrt::BfRtTableData>> counter_part3_data(counter_num);
const bfrt::BfRtTable *counter_part3_table=nullptr;
bf_rt_id_t counter_part3_data_id=0;
bf_rt_id_t counter_part3_data_id2=0;


bf_rt_target_t dev_tgt;
std::shared_ptr<bfrt::BfRtSession> session;



static bf_status_t switch_pktdriver_tx_complete(bf_dev_id_t device,
                                                bf_pkt_tx_ring_t tx_ring,
                                                uint64_t tx_cookie,
                                                uint32_t status) {

  bf_pkt *pkt = (bf_pkt *)(uintptr_t)tx_cookie;
  (void)device;
  (void)tx_ring;
  (void)tx_cookie;
  (void)status;
  bf_pkt_free(device, pkt);
  return 0;
}
void recovery_route_table(struct recover_header &rh)
{
struct rule rl[1000];
    bool newadded[1000];
    uint32_t match[carry_num/4];
    uint32_t prior[carry_num/4];
    for (int j=0;j<1000;j++)
    newadded[j]=0;
    for (int j=0;j<carry_num/4;j++)
    match[j]=0,prior[j]=0;
     if (recoverflag==0)
     {
     std::ifstream fin1("/mnt/onl/data/table10/current_host_conf.txt");
     uint32_t rule_num=0;
     while(!fin1.eof())
     {  
    
       fin1>>std::hex>>rl[rule_num].srcip>>rl[rule_num].srcip_mask>>rl[rule_num].dstip>>rl[rule_num].dstip_mask;
        uint16_t l=0;
       fin1>>std::dec>>l;
       rl[rule_num].protocol=(uint8_t)l;
       fin1>>std::hex>>rl[rule_num].srcport>>rl[rule_num].srcport_mask>>rl[rule_num].dstport>>rl[rule_num].dstport_mask;
       fin1>>std::dec>>rl[rule_num].priority>>rl[rule_num].nexthop;
       rule_num++;
     }
     std::ifstream fin2("/mnt/onl/data/table10/update_conf.txt");
     std::string type;
     fin2>>type;
     if (type=="host")
     {
       while(!fin2.eof())
     {
       std::string method;
       fin2>>method;
       if (method=="add"||method=="mod")
       {
          struct rule m;
          fin2>>std::hex>>m.srcip>>m.srcip_mask>>m.dstip>>m.dstip_mask;
           uint16_t l=0;
       fin2>>std::dec>>l;
       m.protocol=(uint8_t)l;
          fin2>>std::hex>>m.srcport>>m.srcport_mask>>m.dstport>>m.dstport_mask;
          fin2>>std::dec>>m.priority>>m.nexthop;

          for (uint16_t j=0;j<rule_num;j++)
          {
            if (rl[j].srcip==m.srcip&&rl[j].srcip_mask==m.srcip_mask&&rl[j].dstip==m.dstip&&rl[j].dstip_mask==m.dstip_mask&&rl[j].protocol==m.protocol
            &&rl[j].srcport==m.srcport&&rl[j].dstport==m.dstport&&rl[j].priority==m.priority&&rl[j].nexthop==m.nexthop)
            newadded[j]=1;
          }
       }
       else
       {
          fin2>>std::hex>>rl[rule_num].srcip>>rl[rule_num].srcip_mask>>rl[rule_num].dstip>>rl[rule_num].dstip_mask;
           uint16_t l=0;
            fin2>>std::dec>>l;
          rl[rule_num].protocol=(uint8_t)l;
          fin2>>std::hex>>rl[rule_num].srcport>>rl[rule_num].srcport_mask>>rl[rule_num].dstport>>rl[rule_num].dstport_mask;
          fin2>>std::dec>>rl[rule_num].priority>>rl[rule_num].nexthop;
          newadded[rule_num]=1;
          rule_num++;
       }
     }
     }
// then match
     for (uint16_t j=0;j<rh.loss_num;j++)
     {
       for (uint32_t q=0;q<rule_num;q++)
       {
        if (((rh.rF[j].ipsrc&rl[q].srcip_mask)==rl[q].srcip)&&((rh.rF[j].ipdst&rl[q].dstip_mask)==rl[q].dstip)
        &&((rh.rF[j].sport&rl[q].srcport_mask)==rl[q].srcport)&&((rh.rF[j].dport&rl[q].dstport_mask)==rl[q].dstport)&&(rh.rF[j].protocol==rl[q].protocol))
        if (rl[q].priority>prior[j])
        {
          prior[j]=rl[q].priority;
          match[j]=q;
        }
       }
     }
     uint32_t realimpact=0;
     for (uint16_t j=0;j<rh.loss_num;j++)
     {
       if (newadded[match[j]]==1)
       {
         realimpact++;
       }
     }
     if (realimpact>0) //or another threshold
     {
       recoverflag=1;
     }
     }
}

void recovery_ecmp_table(struct recover_header &rh)
{
  std::unique_ptr<bfrt::BfRtTableData> Data;

  fprintf(logs, "loss num: %d\n", rh.loss_num);

   for (int j=0;j<rh.loss_num;j++)
   {
    ipv4_host_table->keyReset(bfrtTableKey.get());
    ipv4_host_table->dataReset(ipv4_host_send_action_id, bfrtTableData.get());
    ipv4_host_table->dataAllocate(&Data);
    bfrtTableKey->setValueandMask(srcip_field_id,rh.rF[j].ipsrc,0xffffffff);
    bfrtTableKey->setValueandMask(dstip_field_id,rh.rF[j].ipdst,0xffffffff);

    fprintf(logs, "src ip: %x\n", rh.rF[j].ipsrc);

    bfrtTableKey->setValueandMask(proto_field_id,rh.rF[j].protocol,0xff);
    bfrtTableKey->setValueandMask(sp_field_id,rh.rF[j].sport,0xffff);
    bfrtTableKey->setValueandMask(dp_field_id,rh.rF[j].dport,0xffff);
     bfrtTableKey->setValue(match_field_id,100);
    bfrtTableData->setValue(send_port_field_id,(uint64_t)rh.rF[j].dst_switch_port);
    if (ipv4_host_table->tableEntryGet(*session,dev_tgt,*(bfrtTableKey.get()),bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_HW,Data.get())!=BF_SUCCESS)
    {

      ipv4_host_table->tableEntryAdd(*session, dev_tgt, *bfrtTableKey, *bfrtTableData);
    }
    else
    {
      ipv4_host_table->tableEntryMod(*session, dev_tgt, *bfrtTableKey, *bfrtTableData);
    }

   }
}

void recovery_link(struct recover_header &rh)
{
  std::unique_ptr<bfrt::BfRtTableData> Data;
   for (int j=0;j<rh.loss_num;j++)
   {
    ipv4_host_table->keyReset(bfrtTableKey.get());
    ipv4_host_table->dataReset(ipv4_host_send_action_id, bfrtTableData.get());
    ipv4_host_table->dataAllocate(&Data);
    bfrtTableKey->setValueandMask(srcip_field_id,rh.rF[j].ipsrc,0x0);
    if (rh.rF[j].ipdst==0)
	        bfrtTableKey->setValueandMask(dstip_field_id,rh.rF[j].ipdst,0x0);
        else
		    bfrtTableKey->setValueandMask(dstip_field_id,rh.rF[j].ipdst,0xffffffff);
    bfrtTableKey->setValueandMask(proto_field_id,rh.rF[j].protocol,0x0);
    bfrtTableKey->setValueandMask(sp_field_id,rh.rF[j].sport,0x0);
    bfrtTableKey->setValueandMask(dp_field_id,rh.rF[j].dport,0x0);
    bfrtTableKey->setValue(match_field_id,0);
    bfrtTableData->setValue(send_port_field_id,(uint64_t)rh.rF[j].dst_switch_port);
    
    if (ipv4_host_table->tableEntryGet(*session,dev_tgt,*(bfrtTableKey.get()),bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_HW,Data.get())!=BF_SUCCESS)
    {

      ipv4_host_table->tableEntryAdd(*session, dev_tgt, *bfrtTableKey, *bfrtTableData);
    }
    else
    {
      ipv4_host_table->tableEntryMod(*session, dev_tgt, *bfrtTableKey, *bfrtTableData);
    }

   }
}
void recovery(struct recover_header &rh)
{
  if (rh.recovery_mode==0)
  {
    recovery_route_table(rh);
  }
  else if (rh.recovery_mode==1)
  {
    recovery_ecmp_table(rh);
  }
   else if (rh.recovery_mode==2)
  {
    recovery_link(rh);
  }
}


bf_status_t rx_packet_callback (bf_dev_id_t dev_id,
   bf_pkt *pkt,
   void *cookie,
   bf_pkt_rx_ring_t rx_ring) {
     (void)dev_id;
     (void)cookie;
     (void)rx_ring;
     printf("Packet received..\n");
    struct recover_header rh;
    
    memcpy(&rh,pkt->pkt_data,sizeof(struct recover_header));
    bf_pkt_free(0,pkt);
     //read
    recovery(rh);
     return 0;
}






void switch_pktdriver_callback_register(bf_dev_id_t device) {

  bf_pkt_tx_ring_t tx_ring;
  bf_pkt_rx_ring_t rx_ring;
  bf_status_t status;
  int cookie;
  /* register callback for TX complete */
  for (tx_ring = BF_PKT_TX_RING_0; tx_ring < BF_PKT_TX_RING_MAX; tx_ring=(bf_pkt_tx_ring_t)(tx_ring+1)) {
    bf_pkt_tx_done_notif_register(
        device, switch_pktdriver_tx_complete, tx_ring);
  }
  /* register callback for RX */
  for (rx_ring = BF_PKT_RX_RING_0; rx_ring < BF_PKT_RX_RING_MAX; rx_ring=(bf_pkt_rx_ring_t)(rx_ring+1)) {
    status = bf_pkt_rx_register(device, rx_packet_callback, rx_ring, (void *) &cookie);
  }
  printf("rx register done. stat = %d\n", status);
}
















void init_ports()
    {
     dev_tgt.dev_id = 0;
  dev_tgt.pipe_id = ALL_PIPES;
  // Get devMgr singleton instance
 bf_pm_port_add_all(dev_tgt.dev_id,BF_SPEED_40G,BF_FEC_TYP_NONE);
bf_pm_port_enable_all(dev_tgt.dev_id);
    if (bf_pkt_is_inited(0)) {
    printf("bf_pkt is initialized\n");
  }

   }

void init_tables()
    {
    system("./bfshell -b /mnt/onl/data/fermat_ecmp/tableinit.py");
   // system("echo exit\n");
   }


namespace bfrt {
namespace examples {
namespace fermat_ecmp {
const bfrt::BfRtInfo *bfrtInfo = nullptr;


//std::unique_ptr<bfrt::BfRtTableKey> bfrtTableKey;
//std::unique_ptr<bfrt::BfRtTableData> bfrtTableData;


void init()
    {
    auto &devMgr = bfrt::BfRtDevMgr::getInstance();
      devMgr.bfRtInfoGet(dev_tgt.dev_id, "fermat_ecmp", &bfrtInfo);
  // Check for status

  // Create a session object
  session = bfrt::BfRtSession::sessionCreate();
   bfrtInfo->bfrtTableFromNameGet("Ingress.timepart", &timepart_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.timeflippart", &timeflippart_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.first_part11", &first_part11_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.second_part11", &second_part11_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.third_part11", &third_part11_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.counter_part11", &counter_part11_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.first_part21", &first_part21_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.second_part21", &second_part21_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.third_part21", &third_part21_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.counter_part21", &counter_part21_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.first_part31", &first_part31_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.second_part31", &second_part31_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.third_part31", &third_part31_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.counter_part31", &counter_part31_table);
  bfrtInfo->bfrtTableFromNameGet("Egress.first_part12", &first_part12_table);
   bfrtInfo->bfrtTableFromNameGet("Egress.second_part12", &second_part12_table);
   bfrtInfo->bfrtTableFromNameGet("Egress.third_part12", &third_part12_table);
   bfrtInfo->bfrtTableFromNameGet("Egress.counter_part12", &counter_part12_table);
   bfrtInfo->bfrtTableFromNameGet("Egress.first_part22", &first_part22_table);
   bfrtInfo->bfrtTableFromNameGet("Egress.second_part22", &second_part22_table);
   bfrtInfo->bfrtTableFromNameGet("Egress.third_part22", &third_part22_table);
   bfrtInfo->bfrtTableFromNameGet("Egress.counter_part22", &counter_part22_table);
   bfrtInfo->bfrtTableFromNameGet("Egress.first_part32", &first_part32_table);
   bfrtInfo->bfrtTableFromNameGet("Egress.second_part32", &second_part32_table);
   bfrtInfo->bfrtTableFromNameGet("Egress.third_part32", &third_part32_table);
   bfrtInfo->bfrtTableFromNameGet("Egress.counter_part32", &counter_part32_table);
    bfrtInfo->bfrtTableFromNameGet("Ingress.first_part1", &first_part1_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.second_part1", &second_part1_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.third_part1", &third_part1_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.counter_part1", &counter_part1_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.first_part2", &first_part2_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.second_part2", &second_part2_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.third_part2", &third_part2_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.counter_part2", &counter_part2_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.first_part3", &first_part3_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.second_part3", &second_part3_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.third_part3", &third_part3_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.counter_part3", &counter_part3_table);
   bfrtInfo->bfrtTableFromNameGet("Ingress.ipv4_host", &ipv4_host_table);
   ipv4_host_table->keyFieldIdGet("hdr.ipv4.src_addr",&srcip_field_id);
   ipv4_host_table->keyFieldIdGet("hdr.ipv4.dst_addr",&dstip_field_id);
   ipv4_host_table->keyFieldIdGet("meta.protocol",&proto_field_id);
   ipv4_host_table->keyFieldIdGet("meta.sp",&sp_field_id);
   ipv4_host_table->keyFieldIdGet("meta.dp",&dp_field_id);
   ipv4_host_table->actionIdGet("Ingress.send", &ipv4_host_send_action_id);
   ipv4_host_table->dataFieldIdGet("port",ipv4_host_send_action_id,&send_port_field_id);
   ipv4_host_table->keyFieldIdGet("$MATCH_PRIORITY",&match_field_id);
   ipv4_host_table->keyAllocate(&bfrtTableKey);
   ipv4_host_table->dataAllocate(&bfrtTableData);
    }

void register_init(const bfrt::BfRtTable* table, std::vector<std::unique_ptr<BfRtTableKey>>& keys, std::vector<std::unique_ptr<BfRtTableData>>& data, std::string data_name, uint32_t entry_num, bf_rt_id_t& data_id)
{
  
 table->dataFieldIdGet(data_name,&data_id);
//get data for table

BfRtTable::keyDataPairs key_data_pairs;
  //std::vector<uint64_t> dt;
  for (unsigned i = 0; i <entry_num; ++i) 
  {
     table->keyAllocate(&keys[i]);
  

     table->dataAllocate(&data[i]);
  
  }
  for (unsigned i = 1; i <  entry_num; ++i) 
  {
   key_data_pairs.push_back(std::make_pair(keys[i].get(), data[i].get()));
  }

  auto flag = bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_HW;
   table->tableEntryGetFirst(
      *session, dev_tgt, flag, keys[0].get(), data[0].get());
        session->sessionCompleteOperations();
  if (entry_num>1)
  {  
  uint32_t num_returned = 0;
   table->tableEntryGetNext_n(*session,dev_tgt,*keys[0].get(), entry_num-1,flag,&key_data_pairs,&num_returned);
    session->sessionCompleteOperations();
  }
}

void register_init_counter(const bfrt::BfRtTable* table, std::vector<std::unique_ptr<BfRtTableKey>>& keys, std::vector<std::unique_ptr<BfRtTableData>>& data, std::string data_name, std::string data_name2, uint32_t entry_num, bf_rt_id_t& data_id, bf_rt_id_t& data_id2)
{
  
 table->dataFieldIdGet(data_name,&data_id);
 table->dataFieldIdGet(data_name2,&data_id2);
//get data for table

BfRtTable::keyDataPairs key_data_pairs;
  //std::vector<uint64_t> dt;
  for (unsigned i = 0; i <entry_num; ++i) 
  {
     table->keyAllocate(&keys[i]);
  

     table->dataAllocate(&data[i]);
  
  }
  for (unsigned i = 1; i <  entry_num; ++i) 
  {
   key_data_pairs.push_back(std::make_pair(keys[i].get(), data[i].get()));
  }

  auto flag = bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_HW;
   table->tableEntryGetFirst(
      *session, dev_tgt, flag, keys[0].get(), data[0].get());
        session->sessionCompleteOperations();
  if (entry_num>1)
  {  
  uint32_t num_returned = 0;
   table->tableEntryGetNext_n(*session,dev_tgt,*keys[0].get(), entry_num-1,flag,&key_data_pairs,&num_returned);
    session->sessionCompleteOperations();
  }
}

void read_register(const bfrt::BfRtTable* table, std::vector<std::unique_ptr<BfRtTableKey>>& keys, std::vector<std::unique_ptr<BfRtTableData>>& data,bf_rt_id_t& data_id,uint32_t entry_num, uint32_t ini)
{
  std::vector<uint64_t> dt;
  for (uint32_t i=0;i<entry_num;i++)
  {
  table->dataAllocate(&data[i]);
   table->tableEntryGet(*session,dev_tgt,*(keys[i].get()),bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_SW,data[i].get());
  }
    
   session->sessionCompleteOperations();
   for (uint32_t i=0;i<entry_num;i++)
   {
    data[i]->getValue(data_id,&dt);
    tf[flag][i+ini]=(uint32_t)dt[0];
    dt.clear();
  }
}





void read_register_flag(const bfrt::BfRtTable* table, std::vector<std::unique_ptr<BfRtTableKey>>& keys, std::vector<std::unique_ptr<BfRtTableData>>& data,bf_rt_id_t& data_id,uint32_t entry_num, uint64_t flag, uint32_t ini)
{
  std::vector<uint64_t> dt;
  uint32_t initial[4]={ini, ini+entry_num/Ingress_port_num/2,ini+entry_num/Ingress_port_num,ini+entry_num/Ingress_port_num/2*3};
   auto s=(flag==0)?entry_num/2:0;
  for (uint32_t i=0;i<entry_num/2;i++)
  {
  table->dataAllocate(&data[i]);
   table->tableEntryGet(*session,dev_tgt,*(keys[i+s].get()),bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_SW,data[i].get());
  }
    
   session->sessionCompleteOperations();
   for (uint32_t i=0;i<entry_num/2;i++)
   {
    data[i]->getValue(data_id,&dt);
    uint32_t k=i/4;
    array[flag][initial[i%4]+k]=(uint32_t)dt[0];
    dt.clear();
  }
}

void read_register_counter(const bfrt::BfRtTable* table, std::vector<std::unique_ptr<BfRtTableKey>>& keys, std::vector<std::unique_ptr<BfRtTableData>>& data,bf_rt_id_t& data_id,bf_rt_id_t& data_id2, uint32_t entry_num,uint64_t flag,uint32_t ini)
{
  std::vector<uint64_t> dt;
  uint32_t initial[4]={ini, ini+entry_num/Ingress_port_num/2,ini+entry_num/Ingress_port_num,ini+entry_num/Ingress_port_num/2*3};
   auto s=(flag==0)?entry_num/2:0;
  for (uint32_t i=0;i<entry_num/2;i++)
  {
  table->dataAllocate(&data[i]);
   table->tableEntryGet(*session,dev_tgt,*(keys[i+s].get()),bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_SW,data[i].get());
  }
    
   session->sessionCompleteOperations();
   for (uint32_t i=0;i<entry_num/2;i++)
   {
    data[i]->getValue(data_id,&dt);
    data[i]->getValue(data_id2,&dt);
    uint32_t k=i/4;
    array[flag][initial[i%4]+k]=(uint32_t)dt[0];
    array[flag][initial[i%4]+k+entry_num/2]=(uint32_t)dt[2];
    dt.clear();
  }
}

void read_register_flag2(const bfrt::BfRtTable* table, std::vector<std::unique_ptr<BfRtTableKey>>& keys, std::vector<std::unique_ptr<BfRtTableData>>& data,bf_rt_id_t& data_id,uint32_t entry_num, uint64_t flag, uint32_t ini)
{
  std::vector<uint64_t> dt;
  uint32_t initial[4]={ini, ini+entry_num/Ingress_port_num/2,ini+entry_num/Ingress_port_num,ini+entry_num/Ingress_port_num/2*3};
   auto s=(flag==0)?entry_num/2:0;
  for (uint32_t i=0;i<entry_num/2;i++)
  {
  table->dataAllocate(&data[i]);
   table->tableEntryGet(*session,dev_tgt,*(keys[i+s].get()),bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_SW,data[i].get());
  }
    
   session->sessionCompleteOperations();
   for (uint32_t i=0;i<entry_num/2;i++)
   {
    data[i]->getValue(data_id,&dt);
    uint32_t k=i/4;
    array2[flag][initial[i%4]+k]=(uint32_t)dt[0];
    dt.clear();
  }
}

void read_register_counter2(const bfrt::BfRtTable* table, std::vector<std::unique_ptr<BfRtTableKey>>& keys, std::vector<std::unique_ptr<BfRtTableData>>& data,bf_rt_id_t& data_id,bf_rt_id_t& data_id2, uint32_t entry_num,uint64_t flag,uint32_t ini)
{
  std::vector<uint64_t> dt;
  uint32_t initial[4]={ini, ini+entry_num/Ingress_port_num/2,ini+entry_num/Ingress_port_num,ini+entry_num/Ingress_port_num/2*3};
   auto s=(flag==0)?entry_num/2:0;
  for (uint32_t i=0;i<entry_num/2;i++)
  {
  table->dataAllocate(&data[i]);
   table->tableEntryGet(*session,dev_tgt,*(keys[i+s].get()),bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_SW,data[i].get());
  }
    
   session->sessionCompleteOperations();
   for (uint32_t i=0;i<entry_num/2;i++)
   {
    data[i]->getValue(data_id,&dt);
    data[i]->getValue(data_id2,&dt);
    uint32_t k=i/4;
    array2[flag][initial[i%4]+k]=(uint32_t)dt[0];
    array2[flag][initial[i%4]+k+entry_num/2]=(uint32_t)dt[2];
    dt.clear();
  }
}




void read_register_flag1(const bfrt::BfRtTable* table, std::vector<std::unique_ptr<BfRtTableKey>>& keys, std::vector<std::unique_ptr<BfRtTableData>>& data,bf_rt_id_t& data_id,uint32_t entry_num, uint64_t flag, uint32_t ini)
{
  std::vector<uint64_t> dt;
   uint32_t initial[4]={ini, ini+entry_num/Ingress_port_num/2,ini+entry_num/Ingress_port_num,ini+entry_num/Ingress_port_num/2*3};
  for (uint32_t i=0;i<entry_num/2;i++)
  {
    auto s=(flag)?entry_num/2:0;

  table->dataAllocate(&data[i]);
   table->tableEntryGet(*session,dev_tgt,*(keys[i+s].get()),bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_SW,data[i].get());
  }
    
   session->sessionCompleteOperations();
   for (uint32_t i=0;i<entry_num/2;i++)
   {
    data[i]->getValue(data_id,&dt);
    uint32_t k=i/4;
    array1[flag][initial[i%4]+k]=(uint32_t)dt[0];
    dt.clear();
  }
}

void read_register_counter1(const bfrt::BfRtTable* table, std::vector<std::unique_ptr<BfRtTableKey>>& keys, std::vector<std::unique_ptr<BfRtTableData>>& data,bf_rt_id_t& data_id,bf_rt_id_t& data_id2, uint32_t entry_num,uint64_t flag,uint32_t ini)
{
  std::vector<uint64_t> dt;
   uint32_t initial[4]={ini, ini+entry_num/Ingress_port_num/2,ini+entry_num/Ingress_port_num,ini+entry_num/Ingress_port_num/2*3};
   for (uint32_t i=0;i<entry_num/2;i++)
  {
    auto s=(flag==0)?entry_num/2:0;

  table->dataAllocate(&data[i]);
   table->tableEntryGet(*session,dev_tgt,*(keys[i+s].get()),bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_SW,data[i].get());
  }
    
   session->sessionCompleteOperations();
   for (uint32_t i=0;i<entry_num/2;i++)
   {
    data[i]->getValue(data_id,&dt);
    data[i]->getValue(data_id2,&dt);
     uint32_t k=i/4;
    array1[flag][initial[i%4]+k]=(uint32_t)dt[0];
    array1[flag][initial[i%4]+k+entry_num/2]=(uint32_t)dt[2];
    dt.clear();
  }
}






void stats_update_cb_timepart_to1(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register(timepart_table, timepart_key,timepart_data,timepart_data_id,Ingress_port_num,0);
  
  return;
}

void stats_update_cb_first_part11_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag(first_part11_table, first_part11_key,first_part11_data,first_part11_data_id,counter_num,flag,0);
  
  return;
}

void stats_update_cb_second_part11_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag(second_part11_table, second_part11_key,second_part11_data,second_part11_data_id,counter_num,flag,counter_num/2);
  
  return;
}

void stats_update_cb_third_part11_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag(third_part11_table, third_part11_key,third_part11_data,third_part11_data_id,counter_num,flag,counter_num);
  
  return;
}
void stats_update_cb_counter_part11_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_counter(counter_part11_table, counter_part11_key,counter_part11_data,counter_part11_data_id,counter_part11_data_id2,counter_num,flag,counter_num*3/2);
  
  return;
}

void stats_update_cb_first_part21_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag(first_part21_table, first_part21_key,first_part21_data,first_part21_data_id,counter_num,flag,counter_num*5/2);
  
  return;
}

void stats_update_cb_second_part21_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag(second_part21_table, second_part21_key,second_part21_data,second_part21_data_id,counter_num,flag,counter_num*3);
  
  return;
}

void stats_update_cb_third_part21_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag(third_part21_table, third_part21_key,third_part21_data,third_part21_data_id,counter_num,flag,counter_num*7/2);
  
  return;
}
void stats_update_cb_counter_part21_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_counter(counter_part21_table, counter_part21_key,counter_part21_data,counter_part21_data_id,counter_part21_data_id2,counter_num,flag,counter_num*4);
  
  return;
}


void stats_update_cb_first_part31_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag(first_part31_table, first_part31_key,first_part31_data,first_part31_data_id,counter_num,flag,counter_num*5);
  
  return;
}

void stats_update_cb_second_part31_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag(second_part31_table, second_part31_key,second_part31_data,second_part31_data_id,counter_num,flag,counter_num*11/2);
  
  return;
}

void stats_update_cb_third_part31_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag(third_part31_table, third_part31_key,third_part31_data,third_part31_data_id,counter_num,flag,counter_num*6);
  
  return;
}
void stats_update_cb_counter_part31_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_counter(counter_part31_table, counter_part31_key,counter_part31_data,counter_part31_data_id,counter_part31_data_id2,counter_num,flag,counter_num*13/2);
  
  return;
}




void stats_update_cb_first_part12_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag2(first_part12_table, first_part12_key,first_part12_data,first_part12_data_id,counter_num,flag,0);
  
  return;
}

void stats_update_cb_second_part12_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag2(second_part12_table, second_part12_key,second_part12_data,second_part12_data_id,counter_num,flag,counter_num/2);
  
  return;
}

void stats_update_cb_third_part12_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag2(third_part12_table, third_part12_key,third_part12_data,third_part12_data_id,counter_num,flag,counter_num);
  
  return;
}
void stats_update_cb_counter_part12_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_counter2(counter_part12_table, counter_part12_key,counter_part12_data,counter_part12_data_id,counter_part12_data_id2,counter_num,flag,counter_num*3/2);
  
  return;
}

void stats_update_cb_first_part22_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag2(first_part22_table, first_part22_key,first_part22_data,first_part22_data_id,counter_num,flag,counter_num*5/2);
  
  return;
}

void stats_update_cb_second_part22_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag2(second_part22_table, second_part22_key,second_part22_data,second_part22_data_id,counter_num,flag,counter_num*3);
  
  return;
}

void stats_update_cb_third_part22_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag2(third_part22_table, third_part22_key,third_part22_data,third_part22_data_id,counter_num,flag,counter_num*7/2);
  
  return;
}
void stats_update_cb_counter_part22_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_counter2(counter_part22_table, counter_part22_key,counter_part22_data,counter_part22_data_id,counter_part22_data_id2,counter_num,flag,counter_num*4);
  
  return;
}


void stats_update_cb_first_part32_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag2(first_part32_table, first_part32_key,first_part32_data,first_part32_data_id,counter_num,flag,counter_num*5);
  
  return;
}

void stats_update_cb_second_part32_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag2(second_part32_table, second_part32_key,second_part32_data,second_part32_data_id,counter_num,flag,counter_num*11/2);
  
  return;
}

void stats_update_cb_third_part32_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag2(third_part32_table, third_part32_key,third_part32_data,third_part32_data_id,counter_num,flag,counter_num*6);
  
  return;
}
void stats_update_cb_counter_part32_to(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_counter2(counter_part32_table, counter_part32_key,counter_part32_data,counter_part32_data_id,counter_part32_data_id2,counter_num,flag,counter_num*13/2);
  
  return;
}













void stats_update_cb_first_part1_to1(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag1(first_part1_table, first_part1_key,first_part1_data,first_part1_data_id,counter_num,flag,0);
  
  return;
}

void stats_update_cb_second_part1_to1(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag1(second_part1_table, second_part1_key,second_part1_data,second_part1_data_id,counter_num,flag,counter_num/2);
  
  return;
}

void stats_update_cb_third_part1_to1(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag1(third_part1_table, third_part1_key,third_part1_data,third_part1_data_id,counter_num,flag,counter_num);
  
  return;
}
void stats_update_cb_counter_part1_to1(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_counter1(counter_part1_table, counter_part1_key,counter_part1_data,counter_part1_data_id,counter_part1_data_id2,counter_num,flag,counter_num*3/2);
  
  return;
}

void stats_update_cb_first_part2_to1(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag1(first_part2_table, first_part2_key,first_part2_data,first_part2_data_id,counter_num,flag,counter_num*5/2);
  
  return;
}

void stats_update_cb_second_part2_to1(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag1(second_part2_table, second_part2_key,second_part2_data,second_part2_data_id,counter_num,flag,counter_num*3);
  
  return;
}

void stats_update_cb_third_part2_to1(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag1(third_part2_table, third_part2_key,third_part2_data,third_part2_data_id,counter_num,flag,counter_num*7/2);
  
  return;
}
void stats_update_cb_counter_part2_to1(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_counter1(counter_part2_table, counter_part2_key,counter_part2_data,counter_part2_data_id,counter_part2_data_id2,counter_num,flag,counter_num*4);
  
  return;
}


void stats_update_cb_first_part3_to1(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag1(first_part3_table, first_part3_key,first_part3_data,first_part3_data_id,counter_num,flag,counter_num*5);
  
  return;
}

void stats_update_cb_second_part3_to1(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag1(second_part3_table, second_part3_key,second_part3_data,second_part3_data_id,counter_num,flag,counter_num*11/2);
  
  return;
}

void stats_update_cb_third_part3_to1(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_flag1(third_part3_table, third_part3_key,third_part3_data,third_part3_data_id,counter_num,flag,counter_num*6);
  
  return;
}
void stats_update_cb_counter_part3_to1(const bf_rt_target_t &dev_tgt, void *cookie) 
{
  (void)dev_tgt;
  (void)cookie;
read_register_counter1(counter_part3_table, counter_part3_key,counter_part3_data,counter_part3_data_id,counter_part3_data_id2,counter_num,flag,counter_num*13/2);
  
  return;
}







void cb_init()
{
timepart_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&timepart_to1);
timepart_to1->registerSyncSet(*session, dev_tgt, stats_update_cb_timepart_to1, NULL);

first_part11_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&first_part11_to);
first_part11_to->registerSyncSet(*session, dev_tgt, stats_update_cb_first_part11_to, NULL);
second_part11_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&second_part11_to);
second_part11_to->registerSyncSet(*session, dev_tgt, stats_update_cb_second_part11_to, NULL);
third_part11_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&third_part11_to);
third_part11_to->registerSyncSet(*session, dev_tgt, stats_update_cb_third_part11_to, NULL);
counter_part11_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&counter_part11_to);
counter_part11_to->registerSyncSet(*session, dev_tgt, stats_update_cb_counter_part11_to, NULL);
first_part21_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&first_part21_to);
first_part21_to->registerSyncSet(*session, dev_tgt, stats_update_cb_first_part21_to, NULL);
second_part21_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&second_part21_to);
second_part21_to->registerSyncSet(*session, dev_tgt, stats_update_cb_second_part21_to, NULL);
third_part21_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&third_part21_to);
third_part21_to->registerSyncSet(*session, dev_tgt, stats_update_cb_third_part21_to, NULL);
counter_part21_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&counter_part21_to);
counter_part21_to->registerSyncSet(*session, dev_tgt, stats_update_cb_counter_part21_to, NULL);
first_part31_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&first_part31_to);
first_part31_to->registerSyncSet(*session, dev_tgt, stats_update_cb_first_part31_to, NULL);
second_part31_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&second_part31_to);
second_part31_to->registerSyncSet(*session, dev_tgt, stats_update_cb_second_part31_to, NULL);
third_part31_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&third_part31_to);
third_part31_to->registerSyncSet(*session, dev_tgt, stats_update_cb_third_part31_to, NULL);
counter_part31_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&counter_part31_to);
counter_part31_to->registerSyncSet(*session, dev_tgt, stats_update_cb_counter_part31_to, NULL);
first_part12_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&first_part12_to);
first_part12_to->registerSyncSet(*session, dev_tgt, stats_update_cb_first_part12_to, NULL);
second_part12_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&second_part12_to);
second_part12_to->registerSyncSet(*session, dev_tgt, stats_update_cb_second_part12_to, NULL);
third_part12_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&third_part12_to);
third_part12_to->registerSyncSet(*session, dev_tgt, stats_update_cb_third_part12_to, NULL);
counter_part12_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&counter_part12_to);
counter_part12_to->registerSyncSet(*session, dev_tgt, stats_update_cb_counter_part12_to, NULL);
first_part22_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&first_part22_to);
first_part22_to->registerSyncSet(*session, dev_tgt, stats_update_cb_first_part22_to, NULL);
second_part22_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&second_part22_to);
second_part22_to->registerSyncSet(*session, dev_tgt, stats_update_cb_second_part22_to, NULL);
third_part22_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&third_part22_to);
third_part22_to->registerSyncSet(*session, dev_tgt, stats_update_cb_third_part22_to, NULL);
counter_part22_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&counter_part22_to);
counter_part22_to->registerSyncSet(*session, dev_tgt, stats_update_cb_counter_part22_to, NULL);
first_part32_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&first_part32_to);
first_part32_to->registerSyncSet(*session, dev_tgt, stats_update_cb_first_part32_to, NULL);
second_part32_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&second_part32_to);
second_part32_to->registerSyncSet(*session, dev_tgt, stats_update_cb_second_part32_to, NULL);
third_part32_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&third_part32_to);
third_part32_to->registerSyncSet(*session, dev_tgt, stats_update_cb_third_part32_to, NULL);
counter_part32_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&counter_part32_to);
counter_part32_to->registerSyncSet(*session, dev_tgt, stats_update_cb_counter_part32_to, NULL);
first_part1_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&first_part1_to1);
first_part1_to1->registerSyncSet(*session, dev_tgt, stats_update_cb_first_part1_to1, NULL);
second_part1_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&second_part1_to1);
second_part1_to1->registerSyncSet(*session, dev_tgt, stats_update_cb_second_part1_to1, NULL);
third_part1_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&third_part1_to1);
third_part1_to1->registerSyncSet(*session, dev_tgt, stats_update_cb_third_part1_to1, NULL);
counter_part1_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&counter_part1_to1);
counter_part1_to1->registerSyncSet(*session, dev_tgt, stats_update_cb_counter_part1_to1, NULL);
first_part2_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&first_part2_to1);
first_part2_to1->registerSyncSet(*session, dev_tgt, stats_update_cb_first_part2_to1, NULL);
second_part2_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&second_part2_to1);
second_part2_to1->registerSyncSet(*session, dev_tgt, stats_update_cb_second_part2_to1, NULL);
third_part2_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&third_part2_to1);
third_part2_to1->registerSyncSet(*session, dev_tgt, stats_update_cb_third_part2_to1, NULL);
counter_part2_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&counter_part2_to1);
counter_part2_to1->registerSyncSet(*session, dev_tgt, stats_update_cb_counter_part2_to1, NULL);
first_part3_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&first_part3_to1);
first_part3_to1->registerSyncSet(*session, dev_tgt, stats_update_cb_first_part3_to1, NULL);
second_part3_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&second_part3_to1);
second_part3_to1->registerSyncSet(*session, dev_tgt, stats_update_cb_second_part3_to1, NULL);
third_part3_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&third_part3_to1);
third_part3_to1->registerSyncSet(*session, dev_tgt, stats_update_cb_third_part3_to1, NULL);
counter_part3_table->operationsAllocate(bfrt::TableOperationsType::REGISTER_SYNC,&counter_part3_to1);
counter_part3_to1->registerSyncSet(*session, dev_tgt, stats_update_cb_counter_part3_to1, NULL);
}


void sync_for_reg(const bfrt::BfRtTable* table, std::unique_ptr<bfrt::BfRtTableOperations>& table_operation)
{
table->tableOperationsExecute(*table_operation.get());
session->sessionCompleteOperations();
}

void filp_time(const bfrt::BfRtTable* table, std::vector<std::unique_ptr<BfRtTableKey>>& keys, std::vector<std::unique_ptr<BfRtTableData>>& data, bf_rt_id_t& data_id )
{
table->dataAllocate(&data[0]);
data[0]->setValue(data_id,flag);
table->tableEntryMod(*session,dev_tgt,*(keys[0].get()),*(data[0].get()));
session->sessionCompleteOperations();
}

}}}
static void parse_options(bf_switchd_context_t *switchd_ctx,
                          int argc,
                          char **argv) {
  int option_index = 0;
  enum opts {
    OPT_INSTALLDIR = 1,
    OPT_CONFFILE,
    OPT_TIME,
  };
  static struct option options[] = {
      {"help", no_argument, 0, 'h'},
      {"install-dir", required_argument, 0, OPT_INSTALLDIR},
      {"conf-file", required_argument, 0, OPT_CONFFILE},
      {"expected-time", required_argument, 0, OPT_TIME}};

  while (1) {
    int c = getopt_long(argc, argv, "h", options, &option_index);

    if (c == -1) {
      break;
    }
    switch (c) {
      case OPT_INSTALLDIR:
        switchd_ctx->install_dir = strdup(optarg);
        printf("Install Dir: %s\n", switchd_ctx->install_dir);
        break;
      case OPT_CONFFILE:
        switchd_ctx->conf_file = strdup(optarg);
        printf("Conf-file : %s\n", switchd_ctx->conf_file);
        break;
      case OPT_TIME:
      expected_time=strtoull(strdup(optarg),NULL,10);
      printf("expected_time : %lu\n", expected_time);
      break;

      case 'h':
      case '?':
        printf("bfrt_perf \n");
        printf(
            "Usage : bfrt_perf --install-dir <path to where the SDE is "
            "installed> --conf-file <full path to the conf file "
            "(bfrt_perf.conf)\n");
        exit(c == 'h' ? 0 : 1);
        break;
      default:
        printf("Invalid option\n");
        exit(0);
        break;
    }
  }
  if (switchd_ctx->install_dir == NULL) {
    printf("ERROR : --install-dir must be specified\n");
    exit(0);
  }

  if (switchd_ctx->conf_file == NULL) {
    printf("ERROR : --conf-file must be specified\n");
    exit(0);
  }
}

int main(int argc, char **argv) {
  bf_switchd_context_t *switchd_ctx;
  //unsigned int ent_per_sec = 0;

  if ((switchd_ctx = (bf_switchd_context_t *)calloc(
           1, sizeof(bf_switchd_context_t))) == NULL) {
    printf("Cannot Allocate switchd context\n");
    exit(1);
  }
  parse_options(switchd_ctx, argc, argv);
  switchd_ctx->running_in_background = true;
  bf_status_t status = bf_switchd_lib_init(switchd_ctx);
  init_tables();
  //init_tables();
    init_ports();
    switch_pktdriver_callback_register(0);
    bfrt::examples::fermat_ecmp::init();
    bfrt::examples::fermat_ecmp::register_init(timepart_table, timepart_key,timepart_data,"Ingress.timepart.f1",Ingress_port_num,timepart_data_id);
    bfrt::examples::fermat_ecmp::register_init(first_part11_table, first_part11_key,first_part11_data,"Ingress.first_part11.f1",counter_num,first_part11_data_id);
     bfrt::examples::fermat_ecmp::register_init(second_part11_table, second_part11_key,second_part11_data,"Ingress.second_part11.f1",counter_num,second_part11_data_id);
     bfrt::examples::fermat_ecmp::register_init(third_part11_table, third_part11_key,third_part11_data,"Ingress.third_part11.f1",counter_num,third_part11_data_id);
     bfrt::examples::fermat_ecmp::register_init_counter(counter_part11_table, counter_part11_key,counter_part11_data,"Ingress.counter_part11.id","Ingress.counter_part11.counter",counter_num,counter_part11_data_id,counter_part11_data_id2);
     bfrt::examples::fermat_ecmp::register_init(first_part21_table, first_part21_key,first_part21_data,"Ingress.first_part21.f1",counter_num,first_part21_data_id);
     bfrt::examples::fermat_ecmp::register_init(second_part21_table, second_part21_key,second_part21_data,"Ingress.second_part21.f1",counter_num,second_part21_data_id);
     bfrt::examples::fermat_ecmp::register_init(third_part21_table, third_part21_key,third_part21_data,"Ingress.third_part21.f1",counter_num,third_part21_data_id);
     bfrt::examples::fermat_ecmp::register_init_counter(counter_part21_table, counter_part21_key,counter_part21_data,"Ingress.counter_part21.id","Ingress.counter_part21.counter",counter_num,counter_part21_data_id,counter_part21_data_id2);
     bfrt::examples::fermat_ecmp::register_init(first_part31_table, first_part31_key,first_part31_data,"Ingress.first_part31.f1",counter_num,first_part31_data_id);
     bfrt::examples::fermat_ecmp::register_init(second_part31_table, second_part31_key,second_part31_data,"Ingress.second_part31.f1",counter_num,second_part31_data_id);
     bfrt::examples::fermat_ecmp::register_init(third_part31_table, third_part31_key,third_part31_data,"Ingress.third_part31.f1",counter_num,third_part31_data_id);
     bfrt::examples::fermat_ecmp::register_init_counter(counter_part31_table, counter_part31_key,counter_part31_data,"Ingress.counter_part31.id","Ingress.counter_part31.counter",counter_num,counter_part31_data_id,counter_part31_data_id2);
     //std::cout<<"YES1"<<std::endl;
     bfrt::examples::fermat_ecmp::register_init(first_part12_table, first_part12_key,first_part12_data,"Egress.first_part12.f1",counter_num,first_part12_data_id);
     //std::cout<<"YES2"<<std::endl;
     bfrt::examples::fermat_ecmp::register_init(second_part12_table, second_part12_key,second_part12_data,"Egress.second_part12.f1",counter_num,second_part12_data_id);
    // std::cout<<"YES3"<<std::endl;
     bfrt::examples::fermat_ecmp::register_init(third_part12_table, third_part12_key,third_part12_data,"Egress.third_part12.f1",counter_num,third_part12_data_id);
     //std::cout<<"YES4"<<std::endl;
     bfrt::examples::fermat_ecmp::register_init_counter(counter_part12_table, counter_part12_key,counter_part12_data,"Egress.counter_part12.id","Egress.counter_part12.counter",counter_num,counter_part12_data_id,counter_part12_data_id2);
     //std::cout<<"YES5"<<std::endl;
     bfrt::examples::fermat_ecmp::register_init(first_part22_table, first_part22_key,first_part22_data,"Egress.first_part22.f1",counter_num,first_part22_data_id);
     bfrt::examples::fermat_ecmp::register_init(second_part22_table, second_part22_key,second_part22_data,"Egress.second_part22.f1",counter_num,second_part22_data_id);
     bfrt::examples::fermat_ecmp::register_init(third_part22_table, third_part22_key,third_part22_data,"Egress.third_part22.f1",counter_num,third_part22_data_id);
     bfrt::examples::fermat_ecmp::register_init_counter(counter_part22_table, counter_part22_key,counter_part22_data,"Egress.counter_part22.id","Egress.counter_part22.counter",counter_num,counter_part22_data_id,counter_part22_data_id2);
     bfrt::examples::fermat_ecmp::register_init(first_part32_table, first_part32_key,first_part32_data,"Egress.first_part32.f1",counter_num,first_part32_data_id);
     bfrt::examples::fermat_ecmp::register_init(second_part32_table, second_part32_key,second_part32_data,"Egress.second_part32.f1",counter_num,second_part32_data_id);
     bfrt::examples::fermat_ecmp::register_init(third_part32_table, third_part32_key,third_part32_data,"Egress.third_part32.f1",counter_num,third_part32_data_id);
     bfrt::examples::fermat_ecmp::register_init_counter(counter_part32_table, counter_part32_key,counter_part32_data,"Egress.counter_part32.id","Egress.counter_part32.counter",counter_num,counter_part32_data_id,counter_part32_data_id2);
    
    bfrt::examples::fermat_ecmp::register_init(first_part1_table, first_part1_key,first_part1_data,"Ingress.first_part1.f1",counter_num,first_part1_data_id);
     bfrt::examples::fermat_ecmp::register_init(second_part1_table, second_part1_key,second_part1_data,"Ingress.second_part1.f1",counter_num,second_part1_data_id);
     bfrt::examples::fermat_ecmp::register_init(third_part1_table, third_part1_key,third_part1_data,"Ingress.third_part1.f1",counter_num,third_part1_data_id);
     bfrt::examples::fermat_ecmp::register_init_counter(counter_part1_table, counter_part1_key,counter_part1_data,"Ingress.counter_part1.id","Ingress.counter_part1.counter",counter_num,counter_part1_data_id,counter_part1_data_id2);
     bfrt::examples::fermat_ecmp::register_init(first_part2_table, first_part2_key,first_part2_data,"Ingress.first_part2.f1",counter_num,first_part2_data_id);
     bfrt::examples::fermat_ecmp::register_init(second_part2_table, second_part2_key,second_part2_data,"Ingress.second_part2.f1",counter_num,second_part2_data_id);
     bfrt::examples::fermat_ecmp::register_init(third_part2_table, third_part2_key,third_part2_data,"Ingress.third_part2.f1",counter_num,third_part2_data_id);
     bfrt::examples::fermat_ecmp::register_init_counter(counter_part2_table, counter_part2_key,counter_part2_data,"Ingress.counter_part2.id","Ingress.counter_part2.counter",counter_num,counter_part2_data_id,counter_part2_data_id2);
     bfrt::examples::fermat_ecmp::register_init(first_part3_table, first_part3_key,first_part3_data,"Ingress.first_part3.f1",counter_num,first_part3_data_id);
     bfrt::examples::fermat_ecmp::register_init(second_part3_table, second_part3_key,second_part3_data,"Ingress.second_part3.f1",counter_num,second_part3_data_id);
     bfrt::examples::fermat_ecmp::register_init(third_part3_table, third_part3_key,third_part3_data,"Ingress.third_part3.f1",counter_num,third_part3_data_id);
     bfrt::examples::fermat_ecmp::register_init_counter(counter_part3_table, counter_part3_key,counter_part3_data,"Ingress.counter_part3.id","Ingress.counter_part3.counter",counter_num,counter_part3_data_id,counter_part3_data_id2);
      
      
      bfrt::examples::fermat_ecmp::register_init(timeflippart_table, timeflippart_key,timeflippart_data,"Ingress.timeflippart.f1",1,timeflippart_data_id);
    bfrt::examples::fermat_ecmp::cb_init();
struct timeval tmv;
gettimeofday(&tmv,NULL);
//std::cout<<tmv.tv_sec<<"   "<<tmv.tv_usec<<"  "<<expected_time<<std::endl;
if (expected_time>0)
usleep((expected_time-tmv.tv_sec)*1000000-tmv.tv_usec);
while (1)
{
  auto start = std::chrono::system_clock::now();
  
  //auto end= std::chrono::high_resolution_clock::now();

  std::thread t1(generate_packets,flag);
  flag=1-flag;
  printf("switch from %lu to %lu!\n",1-flag,flag);

 
  bfrt::examples::fermat_ecmp::filp_time(timeflippart_table, timeflippart_key,timeflippart_data,timeflippart_data_id);
  //maybe some sleep
  auto end1= std::chrono::system_clock::now();
  std::chrono::duration<double> elapsed_seconds = end1-start;
  usleep((0.1-elapsed_seconds.count())*1000000);
  
  bfrt::examples::fermat_ecmp::sync_for_reg(timepart_table,timepart_to1);//then read
  bfrt::examples::fermat_ecmp::sync_for_reg(first_part1_table,first_part1_to1);
  bfrt::examples::fermat_ecmp::sync_for_reg(second_part1_table,second_part1_to1);
  bfrt::examples::fermat_ecmp::sync_for_reg(third_part1_table,third_part1_to1);
  bfrt::examples::fermat_ecmp::sync_for_reg(counter_part1_table,counter_part1_to1);
  bfrt::examples::fermat_ecmp::sync_for_reg(first_part2_table,first_part2_to1);
  bfrt::examples::fermat_ecmp::sync_for_reg(second_part2_table,second_part2_to1);
  bfrt::examples::fermat_ecmp::sync_for_reg(third_part2_table,third_part2_to1);
  bfrt::examples::fermat_ecmp::sync_for_reg(counter_part2_table,counter_part2_to1);
  bfrt::examples::fermat_ecmp::sync_for_reg(first_part3_table,first_part3_to1);
  bfrt::examples::fermat_ecmp::sync_for_reg(second_part3_table,second_part3_to1);
  bfrt::examples::fermat_ecmp::sync_for_reg(third_part3_table,third_part3_to1);
  bfrt::examples::fermat_ecmp::sync_for_reg(counter_part3_table,counter_part3_to1);
  bfrt::examples::fermat_ecmp::sync_for_reg(first_part11_table,first_part11_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(second_part11_table,second_part11_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(third_part11_table,third_part11_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(counter_part11_table,counter_part11_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(first_part21_table,first_part21_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(second_part21_table,second_part21_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(third_part21_table,third_part21_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(counter_part21_table,counter_part21_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(first_part31_table,first_part31_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(second_part31_table,second_part31_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(third_part31_table,third_part31_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(counter_part31_table,counter_part31_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(first_part12_table,first_part12_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(second_part12_table,second_part12_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(third_part12_table,third_part12_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(counter_part12_table,counter_part12_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(first_part22_table,first_part22_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(second_part22_table,second_part22_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(third_part22_table,third_part22_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(counter_part22_table,counter_part22_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(first_part32_table,first_part32_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(second_part32_table,second_part32_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(third_part32_table,third_part32_to);
  bfrt::examples::fermat_ecmp::sync_for_reg(counter_part32_table,counter_part32_to);
  t1.join();
    if (recoverflag==2)
  {
    system("./bfshell -b /mnt/onl/data/fermat_ecmp/update.py");
    recoverflag=0;
  }
  else if (recoverflag==1)
  {
    system("./bfshell -b /mnt/onl/data/fermat_ecmp/recover.py");
    recoverflag=2;
  }
  end1= std::chrono::system_clock::now();
  elapsed_seconds = end1-start;

  usleep((1-elapsed_seconds.count())*1000000);
 //bfrt::examples::fermat_ecmp::read_register(timepart_table, timepart_key,timepart_data,timepart_data_id,Ingress_port_num);
  //bfrt::examples::fermat_ecmp::read_register(first_part11_table, first_part11_key,first_part11_data,first_part11_data_id,counter_num);
  //  /bfrt::examplesfermat_ecmp::read_register(second_part11_table, second_part11_key,second_part11_data,second_part11_data_id,counter_num);

}
  return status;
}
