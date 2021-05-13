/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */
//sendp(Ether()/IP(src='192.168.1.1',dst='192.168.1.3')/TCP(dport=63321,sport=8888)/Raw(load='aaaaaaaa'), iface='ens2') 
#include "mod.h"
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <unistd.h>
#include <rte_ether.h>
#include <sys/time.h>
#include "fermat.h"
#include <rte_atomic.h>
#define RX_RING_SIZE 2048
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8192
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 128
#define link_num 49
#define port_id 0
#define thresh 1
struct rte_mempool *mbuf_pool;
bool avail [link_num][2][3];
uint32_t linkup[link_num][2][3];
uint32_t linkflag[link_num][2][3];
uint32_t decodeavail [link_num][2][3];
uint32_t lasttime [link_num][3];
struct fermat fs[link_num][2][3][array_num][entry_num];
struct fermat temp[link_num][2][3][array_num][entry_num];
struct fermat temp1[link_num][2][3][array_num][entry_num];
struct fermat init[array_num][entry_num];
uint32_t ipdst[switch_num+1]={0,0xC0A8010b,0xC0A8010c,0xC0A8010d,0xC0A8010e,0xC0A8010f,0xC0A80110,0xC0A80111,0xC0A80112,0xC0A80113,0xC0A80114};//={???} initialize
uint32_t poly[array_num] = {0x04C11DB7, 0x741B8CD7};//, 0xDB710641};
uint32_t fp_poly = 0x82608EDB;
struct my_header *my_hdr;
uint32_t fop[link_num][2];
uint32_t enable[link_num];
uint16_t otherport[link_num];
uint16_t otherlink[link_num];
FILE* logs;
uint32_t ipmap[link_num];
uint16_t linkmap[11][4][3]={{{0,0,0},{0,0,0},{0,0,0},{0,0,0}},{{9,1,1},{13,2,2},{17,3,3},{21,4,4}},{{10,5,5},{14,6,6},{18,7,7},{22,8,8}},{{1,9,9},{5,10,10},{27,11,11},{31,12,12}},
{{2,13,13},{6,14,14},{28,15,15},{32,16,16}},{{3,17,17},{7,18,18},{35,19,19},{39,20,20}},{{4,21,21},{8,22,22},{36,23,23},{40,24,24}},
{{0,25,25},{0,26,26},{11,27,27},{15,28,28}},{{0,29,29},{0,30,30},{12,31,31},{16,32,32}},{{0,33,33},{0,34,34},{19,35,35},{23,36,36}},
{{0,37,37},{0,38,38},{20,39,39},{24,40,40}}};
static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = ETHER_MAX_LEN,
	},
};
void initialize()
{
	otherport[1]=0;
	otherport[2]=16;
	otherport[3]=20;
	otherport[4]=12;
	otherport[5]=0;
	otherport[6]=16;
	otherport[7]=20;
	otherport[8]=12;
	otherport[9]=0;
	otherport[10]=16;
	otherport[11]=48;
	otherport[12]=56;
	otherport[13]=0;
	otherport[14]=16;
	otherport[15]=48;
	otherport[16]=56;
	otherport[17]=0;
	otherport[18]=16;
	otherport[19]=48;
	otherport[20]=56;
	otherport[21]=0;
	otherport[22]=16;
	otherport[23]=48;
	otherport[24]=56;
		otherport[25]=4;
	otherport[26]=20;
	otherport[27]=52;
	otherport[28]=60;
		otherport[29]=0;
	otherport[30]=16;
	otherport[31]=48;
	otherport[32]=56;
		otherport[33]=0;
	otherport[34]=16;
	otherport[35]=48;
	otherport[36]=56;
		otherport[37]=0;
	otherport[38]=16;
	otherport[39]=48;
	otherport[40]=56;
	enable[1]=1;
	enable[2]=1;
	enable[3]=1;
	enable[4]=1;
	enable[5]=1;
	enable[6]=1;
	enable[7]=1;
	enable[8]=1;
	enable[9]=1;
	enable[10]=1;
	enable[13]=1;
	enable[14]=1;
	enable[17]=1;
	enable[18]=1;
	enable[21]=1;
	enable[22]=1;
	enable[27]=1;
	enable[28]=1;
	enable[31]=1;
	enable[32]=1;
	enable[35]=1;
	enable[36]=1;
	enable[39]=1;
	enable[40]=1;
	otherlink[1]=9;
	otherlink[2]=13;
	otherlink[3]=17;
	otherlink[4]=21;
	otherlink[5]=10;
	otherlink[6]=14;
	otherlink[7]=18;
	otherlink[8]=22;
	otherlink[9]=1;
	otherlink[10]=5;
	otherlink[11]=27;
	otherlink[12]=31;
	otherlink[13]=2;
	otherlink[14]=6;
	otherlink[15]=28;
	otherlink[16]=32;
	otherlink[17]=3;
	otherlink[18]=7;
	otherlink[19]=35;
	otherlink[20]=39;
	otherlink[21]=4;
	otherlink[22]=8;
	otherlink[23]=36;
	otherlink[24]=40;
	otherlink[25]=0;
	otherlink[26]=0;
	otherlink[27]=11;
	otherlink[28]=15;
	otherlink[29]=0;
	otherlink[30]=0;
	otherlink[31]=12;
	otherlink[32]=16;
	otherlink[33]=0;
	otherlink[34]=0;
	otherlink[35]=19;
	otherlink[36]=23;
	otherlink[37]=0;
	otherlink[38]=0;
	otherlink[39]=20;
	otherlink[40]=24;
	ipmap[1]=0xf;
	ipmap[2]=0xf;
	ipmap[3]=0xf0;
	ipmap[4]=0xf0;
	ipmap[5]=0xf;
	ipmap[6]=0xf;
	ipmap[7]=0xf0;
	ipmap[8]=0xf0;
	ipmap[9]=0xf0;
	ipmap[10]=0xf0;
	ipmap[11]=0x3;
	ipmap[12]=0xc;
	ipmap[13]=0xf0;
	ipmap[14]=0xf0;
	ipmap[15]=0x3;
	ipmap[16]=0xc;
	ipmap[17]=0xf;
	ipmap[18]=0xf;
	ipmap[19]=0x30;
	ipmap[20]=0xc0;
	ipmap[21]=0xf;
	ipmap[22]=0xf;
	ipmap[23]=0x30;
	ipmap[24]=0xc0;
	ipmap[27]=0xfc;
	ipmap[28]=0xfc;
	ipmap[31]=0xf3;
	ipmap[32]=0xf3;
	ipmap[35]=0xcf;
	ipmap[36]=0xcf;
	ipmap[39]=0x3f;
	ipmap[40]=0x3f;
	


}





/*void first_match (struct lossResult* lR, struct Rule* Rl)
{

}*/
void send_flows_to_switches(uint32_t culprit_switch, struct lossResult* lR, uint16_t mode,uint32_t linkid)
{
    struct rte_mbuf *m1[BURST_SIZE];
    struct recover_header *r_hdr;
    uint32_t a=0;
    for (int i=0;i<lR->loss_num;i=i+carry_num/4)
    {
        m1[a]=rte_pktmbuf_alloc(mbuf_pool);
        if (m1[a]!=NULL)
        {
            r_hdr = (struct recover_header *) rte_pktmbuf_append(m1[a], sizeof(struct recover_header));
            uint8_t dstAddr[] = {0x3c, 0xfd, 0xfe, 0xad, 0x82, 0xe0};//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4};// {0xf4, 0xe7, 0xb7, 0xfe, 0xfd, 0x3c};
            uint8_t srcAddr[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x11};
            memcpy(r_hdr->ethdstAddr, dstAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
            memcpy(r_hdr->ethsrcAddr, srcAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
            r_hdr->ethtype=htons(0x88b6);
            r_hdr->ipdstAddr = htonl(ipdst[culprit_switch]);
		//	printf("%lx\n",ipdst[culprit_switch]);
            r_hdr->ipsrcAddr = htonl(0x0a000002);
            r_hdr->loss_num=(lR->loss_num-i<carry_num/4)?lR->loss_num-i:carry_num/4;
			r_hdr->recovery_mode=mode;
            for (int j=0;j<r_hdr->loss_num;j++)
            {
                r_hdr->rF[j].ipsrc=lR->f[i+j].ipsrc;
                r_hdr->rF[j].ipdst=lR->f[i+j].ipdst;
                r_hdr->rF[j].sport=lR->f[i+j].src_port;
                r_hdr->rF[j].dport=lR->f[i+j].dst_port;
                r_hdr->rF[j].protocol=lR->f[i+j].protocol;
				//printf("%x\n",+lR->f[i+j].protocol);
				if (mode>0)
				r_hdr->rF[j].dst_switch_port=otherport[linkid];
				else
				r_hdr->rF[j].dst_switch_port=0;
            }
			printf("send to switch %u for link %u\n",culprit_switch,linkid);
            a++;
        }
        else{i-=carry_num/4;}
    }
    uint32_t nb_tx = rte_eth_tx_burst(port_id, 0, &m1[0], a);
    if (nb_tx<a)
    {
        for (int i=nb_tx;i<a;i++)
		rte_pktmbuf_free(m1[i]);
    }
}

void recovery_link(uint32_t linkid)
{
	
	if (enable[linkid])
	{
		struct lossResult rp;
		rp.loss_num=0;
		for (int i=0;i<8;i++)
		{
			if ((ipmap[linkid]&(1<<i))!=0)
			{
		rp.f[rp.loss_num].ipsrc=0x0;
		rp.f[rp.loss_num].ipdst=0xC0A80100+i+1;
		rp.f[rp.loss_num].src_port=0;
		rp.f[rp.loss_num].dst_port=0;
		rp.f[rp.loss_num].protocol=0;
		rp.loss_num++;}
		}
		

		send_flows_to_switches((linkid-1)/4+1,&rp,2,linkid);
	}
	if (!enable[linkid])
	{
		struct lossResult rp;
		rp.loss_num=0;
		for (int i=0;i<8;i++)
		{
			if ((ipmap[linkid]&(1<<i))!=0)
			{
		rp.f[rp.loss_num].ipsrc=0x0;
		rp.f[rp.loss_num].ipdst=0xC0A80100+i+1;
		rp.f[rp.loss_num].src_port=0;
		rp.f[rp.loss_num].dst_port=0;
		rp.f[rp.loss_num].protocol=0;
		rp.loss_num++;}
		}
		uint32_t offset=(linkid-1)%4;
		uint32_t linkid1=((linkid-1)/4)*4+1;
		uint32_t linkid2=((linkid-1)/4)*4+2;
		uint32_t linkid3=((linkid-1)/4)*4+6-offset;
		send_flows_to_switches((otherlink[linkid1]-1)/4+1,&rp,2,otherlink[linkid1]);
		send_flows_to_switches((otherlink[linkid2]-1)/4+1,&rp,2,otherlink[linkid2]);
		send_flows_to_switches((otherlink[linkid3]-1)/4+1,&rp,2,otherlink[linkid3]);
	}
	if (otherlink[linkid]>0&&enable[otherlink[linkid]])
	{
		struct lossResult rp;
		rp.loss_num=0;
		for (int i=0;i<8;i++)
		{
			if ((ipmap[otherlink[linkid]]&(1<<i))!=0)
			{
		rp.f[rp.loss_num].ipsrc=0x0;
		rp.f[rp.loss_num].ipdst=0xC0A80100+i+1;
		rp.f[rp.loss_num].src_port=0;
		rp.f[rp.loss_num].dst_port=0;
		rp.f[rp.loss_num].protocol=0;
		rp.loss_num++;}
		}
		send_flows_to_switches((otherlink[linkid]-1)/4+1,&rp,2,otherlink[linkid]);
	}
	if (otherlink[linkid]>0&&(!enable[otherlink[linkid]]))
	{
		struct lossResult rp;
		rp.loss_num=0;
		for (int i=0;i<8;i++)
		{
			if ((ipmap[otherlink[linkid]]&(1<<i))!=0)
			{
		rp.f[rp.loss_num].ipsrc=0x0;
		rp.f[rp.loss_num].ipdst=0xC0A80100+i+1;
		rp.f[rp.loss_num].src_port=0;
		rp.f[rp.loss_num].dst_port=0;
		rp.f[rp.loss_num].protocol=0;
		rp.loss_num++;}
		}
		uint32_t offset=(otherlink[linkid]-1)%4;
		uint32_t linkid1=((otherlink[linkid]-1)/4)*4+1;
		uint32_t linkid2=((otherlink[linkid]-1)/4)*4+2;
		uint32_t linkid3=((otherlink[linkid]-1)/4)*4+6-offset;
		send_flows_to_switches((otherlink[linkid1]-1)/4+1,&rp,2,otherlink[linkid1]);
		send_flows_to_switches((otherlink[linkid2]-1)/4+1,&rp,2,otherlink[linkid2]);
		send_flows_to_switches((otherlink[linkid3]-1)/4+1,&rp,2,otherlink[linkid3]);
	}
}


void decide_which_flow_to_recovery()
{
	
}

void decide_which_flow_to_change_path(struct lossResult *lR, uint32_t linkid)
{
	struct lossResult finallR;
	int loss_num=0;
	for (int i=0;i<lR->loss_num;i++)
	{
		if (lR->f[i].counter>=thresh)
		{
			finallR.f[loss_num].ipsrc=lR->f[i].ipsrc;
			finallR.f[loss_num].ipdst=lR->f[i].ipdst;
			finallR.f[loss_num].src_port=lR->f[i].src_port;
			finallR.f[loss_num].dst_port=lR->f[i].dst_port;
			finallR.f[loss_num].protocol=lR->f[i].protocol;
			loss_num++;
		}
	}
	finallR.loss_num=loss_num;
	send_flows_to_switches((linkid-1)/4+1,&finallR,1,linkid);
}





/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	rte_eth_dev_info_get(port, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	printf("nb_rxd=%d,nb_txd=%d\n",nb_rxd,nb_txd);
	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	char port_name[256];
	rte_eth_dev_get_name_by_port(port, port_name);
	printf("port name=%s\n", port_name);
	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

/*static void
fill_ethernet_header(struct ether_hdr *hdr) {
	struct ether_addr s_addr = {{0x14,0x02,0xEC,0x89,0x8D,0x24}};
	static struct ether_addr d_addr = {{0x01,0x50,0x56,0x97,0x5A,0xBF}};
	d_addr.addr_bytes[0] = 0;
	d_addr.addr_bytes[1] = 0;
	d_addr.addr_bytes[2] = 0;
	hdr->s_addr =s_addr;
	hdr->d_addr =d_addr;
	hdr->ether_type = rte_cpu_to_be_16(0x0800);
	printf("dmac_addr: %02X:%02X:%02X:%02X:%02X:%02X\n",
			d_addr.addr_bytes[0], d_addr.addr_bytes[1],
			d_addr.addr_bytes[2], d_addr.addr_bytes[3],
			d_addr.addr_bytes[4], d_addr.addr_bytes[5]);
}
*/
/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static void initializing(void)
{
	printf("start initializing\n");
	uint32_t start=1;
	uint32_t end=40;
	while(1)
	{
		for (int i=start;i<=end;i++)
		{
			
			for (int j=0;j<2;j++)
			for (int k=0;k<3;k++)
			if (avail[i][j][k]==1)
			{
				rte_smp_rmb();
				//printf("%d %d %d\n",i,j,k);
				for (int i1=0;i1<array_num;i1++)
				for (int j1=0;j1<entry_num;j1++)
				{	linkup[i][1-j][k]=0;
					linkup[i][j][k]=1;
					if (fop[i][j]==1)			
					{	temp[i][j][k][i1][j1].ipsrc=htonl(temp[i][j][k][i1][j1].ipsrc);
						temp[i][j][k][i1][j1].ipdst=htonl(temp[i][j][k][i1][j1].ipdst);
						temp[i][j][k][i1][j1].sdport=htonl(temp[i][j][k][i1][j1].sdport);
						temp[i][j][k][i1][j1].rest=htonl(temp[i][j][k][i1][j1].rest);
						temp[i][j][k][i1][j1].counter=htonl(temp[i][j][k][i1][j1].counter);
						fs[i][j][k][i1][j1].ipsrc=
						(temp[i][j][k][i1][j1].ipsrc>=temp1[i][j][k][i1][j1].ipsrc)?
						temp[i][j][k][i1][j1].ipsrc-temp1[i][j][k][i1][j1].ipsrc:
						temp[i][j][k][i1][j1].ipsrc+(PRIME-temp1[i][j][k][i1][j1].ipsrc);
						fs[i][j][k][i1][j1].ipdst=
						(temp[i][j][k][i1][j1].ipdst>=temp1[i][j][k][i1][j1].ipdst)?
						temp[i][j][k][i1][j1].ipdst-temp1[i][j][k][i1][j1].ipdst:
						temp[i][j][k][i1][j1].ipdst+(PRIME-temp1[i][j][k][i1][j1].ipdst);
						fs[i][j][k][i1][j1].sdport=
						(temp[i][j][k][i1][j1].sdport>=temp1[i][j][k][i1][j1].sdport)?
						temp[i][j][k][i1][j1].sdport-temp1[i][j][k][i1][j1].sdport:
						temp[i][j][k][i1][j1].sdport+(PRIME-temp1[i][j][k][i1][j1].sdport);
						fs[i][j][k][i1][j1].rest=
						(temp[i][j][k][i1][j1].rest>=temp1[i][j][k][i1][j1].rest)?
						temp[i][j][k][i1][j1].rest-temp1[i][j][k][i1][j1].rest:
						temp[i][j][k][i1][j1].rest+(PRIME-temp1[i][j][k][i1][j1].rest);
						fs[i][j][k][i1][j1].counter=
						(temp[i][j][k][i1][j1].counter>=temp1[i][j][k][i1][j1].counter)?
						temp[i][j][k][i1][j1].counter-temp1[i][j][k][i1][j1].counter:
						temp[i][j][k][i1][j1].counter+(PRIME-temp1[i][j][k][i1][j1].counter);

					}
					else
					{
						temp1[i][j][k][i1][j1].ipsrc=htonl(temp1[i][j][k][i1][j1].ipsrc);
						temp1[i][j][k][i1][j1].ipdst=htonl(temp1[i][j][k][i1][j1].ipdst);
						temp1[i][j][k][i1][j1].sdport=htonl(temp1[i][j][k][i1][j1].sdport);
						temp1[i][j][k][i1][j1].rest=htonl(temp1[i][j][k][i1][j1].rest);
						temp1[i][j][k][i1][j1].counter=htonl(temp1[i][j][k][i1][j1].counter);
						fs[i][j][k][i1][j1].ipsrc=
						(temp1[i][j][k][i1][j1].ipsrc>=temp[i][j][k][i1][j1].ipsrc)?
						temp1[i][j][k][i1][j1].ipsrc-temp[i][j][k][i1][j1].ipsrc:
						temp1[i][j][k][i1][j1].ipsrc+(PRIME-temp[i][j][k][i1][j1].ipsrc);
						fs[i][j][k][i1][j1].ipdst=
						(temp1[i][j][k][i1][j1].ipdst>=temp[i][j][k][i1][j1].ipdst)?
						temp1[i][j][k][i1][j1].ipdst-temp[i][j][k][i1][j1].ipdst:
						temp1[i][j][k][i1][j1].ipdst+(PRIME-temp[i][j][k][i1][j1].ipdst);
						fs[i][j][k][i1][j1].sdport=
						(temp1[i][j][k][i1][j1].sdport>=temp[i][j][k][i1][j1].sdport)?
						temp1[i][j][k][i1][j1].sdport-temp[i][j][k][i1][j1].sdport:
						temp1[i][j][k][i1][j1].sdport+(PRIME-temp[i][j][k][i1][j1].sdport);
						fs[i][j][k][i1][j1].rest=
						(temp1[i][j][k][i1][j1].rest>=temp[i][j][k][i1][j1].rest)?
						temp1[i][j][k][i1][j1].rest-temp[i][j][k][i1][j1].rest:
						temp1[i][j][k][i1][j1].rest+(PRIME-temp[i][j][k][i1][j1].rest);
						fs[i][j][k][i1][j1].counter=
						(temp1[i][j][k][i1][j1].counter>=temp[i][j][k][i1][j1].counter)?
						temp1[i][j][k][i1][j1].counter-temp[i][j][k][i1][j1].counter:
						temp1[i][j][k][i1][j1].counter+(PRIME-temp[i][j][k][i1][j1].counter);
					}
					if (fs[i][j][k][i1][j1].counter>0)
					{
						linkup[i][j][k]=2;
					}

					
				}
				rte_smp_wmb();
				avail[i][j][k]=0;
				if (k==2)
				decodeavail[i][j][k]=2;
				else
				decodeavail[i][j][k]=1;
				
			}
		}
		

	}
}

static void decoding(void)
{
	printf("start decoding\n");
	uint32_t start=1;
	uint32_t end=40;
	while(1)
	{
		for (int i=start;i<=end;i++)
		{
			
			for (int j=0;j<2;j++)
			{
				if (decodeavail[i][j][1]>0&&decodeavail[i][j][2]>0)
				{	
					rte_smp_rmb();
					struct lossResult* res1=NULL;
					uint32_t countup=0,countdown=0;
					for (int f1=0;f1<2;f1++)
					{	countup=countdown=0;
						for (int f2=0;f2<entry_num;f2++)
					{
						//if (fs[i][j][1][f1][f2].counter>0)
						//
						
						countup+=fs[i][j][1][f1][f2].counter;
						countdown+=fs[i][j][2][f1][f2].counter;
						//printf("%d",countup-countdown);
						//printf("%d %d %d %d %x %x %x %x %d\n",i,j,f1,f2,fs[i][j][1][f1][f2].ipsrc,fs[i][j][1][f1][f2].ipdst,fs[i][j][1][f1][f2].sdport,fs[i][j][1][f1][f2].rest,fs[i][j][1][f1][f2].counter);
					}
					printf("%d %d %d\n",countup,countdown,countup-countdown);
					}
					
					res1 = decode(fs[i][j][1],fs[i][j][2], poly, fp_poly);
					decodeavail[i][j][1]--;
					decodeavail[i][j][2]--;
					if (res1!=NULL)
					{
						printf("linkid: %d loss_num: %d\n",i,res1->loss_num);
						fprintf(logs,"linkid: %d upstream traffic: %d packet_lossnum: %d loss_num: %d\n",i,countup,countup-countdown, res1->loss_num);
						if (countup>0&&countdown==0)
													{
																					recovery_link(i);  
																											}
												else
												{//	if (enable[i]&&res1->loss_num>0)
					//	decide_which_flow_to_change_path(res1,i);				
						}
							}
					else fprintf(logs,"linkid: %d upstream traffic: %d packet_lossnum: %d loss_num: %d\n",i,countup,countup-countdown, -1);
				}
			
			if (decodeavail[i][j][2]>0&&decodeavail[i][j][0]>0)
			{	
				struct lossResult* res1=NULL;
				res1 = decode(fs[i][j][2],fs[i][j][0], poly, fp_poly);
				decodeavail[i][j][2]--;
				decodeavail[i][j][0]--;
			}
		}
		}

	}
}

static void lcore_main(void)
{
	uint16_t port;
	uint32_t cur;
	
	struct rte_mbuf *m1[BURST_SIZE];
	uint32_t upper;
	uint16_t nb_rx;
    uint32_t total;
	int idx[3];
    clock_t start, finish;
	double total_t;
	int s1,s2;
	s1=0;s2=0;
	cur=0;
	int i;
	
/*	printf("\nCore %u sending packets. [Ctrl+C to quit]\n",
			rte_lcore_id());
			recovery_link(40);*/
			/*
	send_flows_to_switches(10,&rp,1,40);*/
	
	
	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */



	printf("\nCore %u receiving packets. [Ctrl+C to quit]\n",
			rte_lcore_id());
		while (1)
		{
			nb_rx= rte_eth_rx_burst(port_id, 0, &m1[0], BURST_SIZE);
		if (nb_rx>0)
			{
				cur=cur+nb_rx;
				//printf("yes\n");
				//printf("%d\n",cur);
			}
			for (i=0;i<nb_rx;i++)
			{	
				//printf("yes\n");
				
				my_hdr = rte_pktmbuf_mtod_offset(m1[i], struct my_header *, 0);
				
			
            	
				if (my_hdr->ethtype==htons(0x88b5))
				{
					
					uint16_t true_filled_index=ntohs(my_hdr->filled_index);
					//printf("%u %u %u %u\n",(my_hdr->ip_src_addr>>24)-0xa,true_filled_index&3,(true_filled_index)>>10,(true_filled_index>>2)&(entry_num-1));
					uint32_t linkidu_m=linkmap[(my_hdr->ip_src_addr>>24)-0xa][true_filled_index&3][1];
					uint32_t linkidd=linkmap[(my_hdr->ip_src_addr>>24)-0xa][true_filled_index&3][0];
					uint32_t timeflag=(true_filled_index)>>11;
					uint16_t index=(true_filled_index>>2)&(entry_num-1);
					if (linkidu_m>0)
					{
						if (fop[linkidu_m][timeflag]==0)
						{
							memcpy(&temp[linkidu_m][timeflag][1][0][index],my_hdr->fermat11,20);
							memcpy(&temp[linkidu_m][timeflag][1][1][index],my_hdr->fermat12,20);
							memcpy(&temp[linkidu_m][timeflag][2][0][index],my_hdr->fermat21,20);
							memcpy(&temp[linkidu_m][timeflag][2][1][index],my_hdr->fermat22,20);
						}
						else
						{
							memcpy(&temp1[linkidu_m][timeflag][1][0][index],my_hdr->fermat11,20);
							memcpy(&temp1[linkidu_m][timeflag][1][1][index],my_hdr->fermat12,20);
							memcpy(&temp1[linkidu_m][timeflag][2][0][index],my_hdr->fermat21,20);
							memcpy(&temp1[linkidu_m][timeflag][2][1][index],my_hdr->fermat22,20);
						}
					}
					if (linkidd>0)
					{
						if (fop[linkidd][timeflag]==0)
						{
							memcpy(&temp[linkidd][timeflag][0][0][index],my_hdr->fermat01,20);
							memcpy(&temp[linkidd][timeflag][0][1][index],my_hdr->fermat02,20);
						}
						else
						{
							memcpy(&temp1[linkidd][timeflag][0][0][index],my_hdr->fermat01,20);
							memcpy(&temp1[linkidd][timeflag][0][1][index],my_hdr->fermat02,20);
						}
					}
					if (index==entry_num-1)
					{	
						rte_smp_wmb();
						//printf("%d\n",cur);
						fop[linkidu_m][timeflag]=1-fop[linkidu_m][timeflag];
						fop[linkidd][timeflag]=1-fop[linkidd][timeflag];
						if (linkidu_m>0)
						{
							avail[linkidu_m][timeflag][1]=1;
						
							avail[linkidu_m][timeflag][2]=1;
							avail[linkidu_m][1-timeflag][1]=0;
							avail[linkidu_m][1-timeflag][2]=0;
							//printf("linkid:%d\n",linkidu_m);
							decodeavail[linkidu_m][1-timeflag][1]=0;
							decodeavail[linkidu_m][1-timeflag][2]=0;
						}
						if (linkidd>0)
						{
							//printf("linkidd:%d\n",linkidu_m);
							avail[linkidd][timeflag][0]=1;
							avail[linkidd][1-timeflag][0]=0;
							decodeavail[linkidd][1-timeflag][0]=0;
						}

					
						//printf("yes1\n");
						
						//printf("yes2\n");
					}
					//printf("%u\n",my_hdr->ip_dst_addr);
				}
				rte_pktmbuf_free(m1[i]);
			}

			
		}
			
}
		


/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	unsigned nb_ports;
	uint16_t portid;
	logs=fopen("logs","w");
	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	argc -= ret;
	argv += ret;

	/* Check that there is one port to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();

	initialize();
	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, 9000, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
		if (port_init(port_id, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					port_id);
		


	/* Call lcore_main on the master core only. */
rte_eal_remote_launch(initializing, NULL, 17);
rte_eal_remote_launch(decoding, NULL, 18);
lcore_main();

		rte_eth_dev_stop(port_id);
		rte_eth_dev_close(port_id);
		printf(" Done\n");


	return 0;
}

