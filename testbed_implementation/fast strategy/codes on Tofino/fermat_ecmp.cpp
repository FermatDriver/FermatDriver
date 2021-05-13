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
  struct recoverFlow rF[carry_num/4];
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

/*typedef struct __attribute__((__packed__)) tcp_t {
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
			        uint32_t payload[8];
} tcp;*/



typedef struct __attribute__((__packed__)) tcp_t {
  uint8_t ethdstAddr[6];
  uint8_t ethsrcAddr[6];
  uint16_t ethtype;
  uint32_t ipsrcAddr;
  uint32_t ipdstAddr;
uint16_t filled_index;
uint32_t payload[10];

} tcp;



#define ALL_PIPES 0xffff
#define Ingress_port_num 4
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

void generate_and_send (uint64_t timeflag) {
  bf_pkt *bftcppkt = NULL;
  tcp tcp_pkt;
  while (1) {
    if (bf_pkt_alloc(0, &bftcppkt, tcp_pkt_sz, (enum bf_dma_type_e)(17)) == 0)
	    break;
    else printf("failed alloc\n");
  }
  uint8_t dstAddr[] = {0x3c, 0xfd, 0xfe, 0xad, 0x82, 0xe0};//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4};// {0xf4, 0xe7, 0xb7, 0xfe, 0xfd, 0x3c};
  uint8_t srcAddr[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x11};
  memcpy(tcp_pkt.ethdstAddr, dstAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
  memcpy(tcp_pkt.ethsrcAddr, srcAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
  tcp_pkt.ethtype=htons(0x88b5);
  tcp_pkt.ipdstAddr = htonl(0xC0A80115);
  tcp_pkt.ipsrcAddr = htonl(0xC0A80109);
  //tcp_pkt.linkid1=linkmap[index%4][0];
  //tcp_pkt.linkid2=linkmap[index%4][1];
  tcp_pkt.filled_index=(uint16_t)timeflag;
  uint8_t * tpkt = (uint8_t *) malloc(tcp_pkt_sz);
  memcpy(tpkt, &tcp_pkt, tcp_pkt_sz);
  if (bf_pkt_data_copy(bftcppkt, tpkt, tcp_pkt_sz) != 0) {
    printf("Failed data copy\n");
  }

  bf_status_t stat = bf_pkt_tx(0, bftcppkt, (bf_pkt_tx_ring_t)(0), (void *)bftcppkt);
  if (stat  != BF_SUCCESS) 
  {
    printf("Failed to send packet status=%s\n", bf_err_str(stat));
    bf_pkt_free(0,bftcppkt);
  }
  //else std::cout<<"sent"<<uod<<std::endl;
  
}
/*void generate_packets(uint32_t timeflag)
{
    uint16_t st=(timeflag==0)?counter_num/2:0;
    for (int i=0;i<counter_num/2;i++)
    {
        generate_and_send(st+i,1-timeflag);
    }*/
/*	  auto start = std::chrono::system_clock::now();
	      uint16_t st=(timeflag==0)?counter_num/2:0;
	          for (int i=0;i<counter_num/4;i++)
			      {
				              generate_and_send(st+i,1-timeflag);
					          }
		      auto end = std::chrono::system_clock::now();
		          std::chrono::duration<double> elapsed_seconds = end-start;
			      std::cout<<elapsed_seconds.count()<<std::endl;
			          for (int i=counter_num/4;i<counter_num/2;i++)
					      {
						              generate_and_send(st+i,1-timeflag);
							          }
				      auto end1 = std::chrono::system_clock::now();
				          elapsed_seconds = end1-end;
					      std::cout<<elapsed_seconds.count()<<std::endl;

}*/
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
     std::ifstream fin1("/mnt/onl/data/table/current_host_conf.txt");
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
     std::ifstream fin2("/mnt/onl/data/table/update_conf.txt");
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
   for (int j=0;j<rh.loss_num;j++)
   {
    ipv4_host_table->keyReset(bfrtTableKey.get());
    ipv4_host_table->dataReset(ipv4_host_send_action_id, bfrtTableData.get());
    ipv4_host_table->dataAllocate(&Data);
    bfrtTableKey->setValueandMask(srcip_field_id,rh.rF[j].ipsrc,0xffffffff);
    bfrtTableKey->setValueandMask(dstip_field_id,rh.rF[j].ipdst,0xffffffff);
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
    system("./bfshell -b /mnt/onl/data/new_fermat_ecmp/tableinit.py");
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
   bfrtInfo->bfrtTableFromNameGet("Ingress.timeflippart", &timeflippart_table);
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
      bfrt::examples::fermat_ecmp::register_init(timeflippart_table, timeflippart_key,timeflippart_data,"Ingress.timeflippart.f1",1,timeflippart_data_id);
struct timeval tmv;
gettimeofday(&tmv,NULL);
uint32_t interval=10;
uint32_t times=0;
std::cout<<tmv.tv_sec<<"   "<<tmv.tv_usec<<"  "<<expected_time<<std::endl;
if (expected_time>0)
usleep((expected_time-tmv.tv_sec)*1000000-tmv.tv_usec);
while (1)
{
  flag=1-flag;
  bfrt::examples::fermat_ecmp::filp_time(timeflippart_table, timeflippart_key,timeflippart_data,timeflippart_data_id);
  times++;
  usleep(2000);
  generate_and_send(flag);
  gettimeofday(&tmv,NULL);
  		//printf("%u,%lu \n",times,expected_time*1000000+times*interval*1000-tmv.tv_sec*1000000-tmv.tv_usec);
usleep(expected_time*1000000+times*interval*1000-tmv.tv_sec*1000000-tmv.tv_usec);

}
  return status;
}
