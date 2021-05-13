/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <unistd.h>
#include <rte_ether.h>
#include "murmur3.h"
#include <time.h>
#include<sys/time.h>
#define RX_RING_SIZE 2048
#define TX_RING_SIZE 2048
#define portid 1
#define NUM_MBUFS 8192
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 64
int l1=0;
uint64_t expected_time;
uint32_t switchip[11]={0,0xC0A8010b,0xC0A8010c,0xC0A8010d,0xC0A8010e,0xC0A8010f,0xC0A80110,0xC0A80111,0xC0A80112,0xC0A80113,0xC0A80114};//={???} initialize
struct rte_mempool *mbuf_pool;
struct rte_mempool *mbuf_pool1[4];
struct  __attribute__((__packed__)) my_header
{
  uint8_t ethdstAddr[6];
  uint8_t ethsrcAddr[6];
   uint16_t ethtype;
  uint32_t ip_src_addr;
	uint32_t ip_dst_addr;
    uint16_t filled_index;
	uint32_t payload[10];
};


static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = ETHER_MAX_LEN,
	},
};

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
void get_fermat_from_a_switch(uint32_t CPA, uint32_t switch_id,uint32_t timeflag,uint32_t qid,struct rte_mempool* mbuf_pool)
{
	uint32_t transmitted=(timeflag==0)?CPA:0;
	uint32_t total=(timeflag==0)?(CPA*2):CPA;
	uint32_t tx_pkt=0;
	uint32_t nb_tx;
	uint32_t required;
	struct my_header *my_hdr;
	struct rte_mbuf *m1[BURST_SIZE];
	while (transmitted<total)
	{
			tx_pkt=0;
			if (total-transmitted<BURST_SIZE)
			required=total-transmitted;
			else
			required=BURST_SIZE;
			if (rte_pktmbuf_alloc_bulk(mbuf_pool, (void **)m1, required)==0)
			{tx_pkt=required;}
			


			for (int i=0;i<tx_pkt;i++)
			{	

				my_hdr = (struct my_header *) rte_pktmbuf_append(m1[i], sizeof(struct my_header));

				my_hdr->ethtype=htons(0x88b5);

				my_hdr->ip_src_addr = htonl(0xC0A80109);
				
            	my_hdr->ip_dst_addr = htonl(switchip[switch_id]);
/*		uint16_t small=0;
				if (((transmitted+i)&1)==0)
									small=2;
								else small=1;

												my_hdr->filled_index=htons(transmitted*2+small+2*i);
	*/			my_hdr->filled_index=htons(transmitted+i);
				//printf("%u  %d\n",m1[i]->data_len,l1);
			}
			if (tx_pkt>0)
			{
				//nb_tx = rte_eth_tx_burst(portid, qid, &m1[0], tx_pkt);
				nb_tx = rte_eth_tx_burst(portid, (qid), &m1[0], tx_pkt);
				if (nb_tx<tx_pkt)
				{	
					for (int i=nb_tx;i<tx_pkt;i++)
					rte_pktmbuf_free(m1[i]);
				}
				transmitted=transmitted+nb_tx;

			}
			
		}
}


static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 16;
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
static void lcore_main(void)
{
	uint16_t port;
	uint32_t upper;
	uint16_t nb_tx;
	uint16_t nb_rx;
	uint16_t tx_pkt;
    uint32_t total;
	int idx[3];
	uint32_t cur=0;
	total=0;
	uint32_t qid=0;
	struct rte_mempool * pools;
	int start=0;
	int end=0;
	struct my_header* my_hdr;
	struct rte_mbuf *m1[32];
	unsigned lcore_id = rte_lcore_id();
	if (lcore_id==4)
	{start=1;end=5;qid=0;pools=mbuf_pool;}
	else
	{start=6;end=10;qid=8;pools=mbuf_pool1[1];}
	
	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
    printf("Starting core on queue %u %u\n", lcore_id,qid);
	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());
	struct timeval tmv;
	gettimeofday(&tmv,NULL);
	printf("%lu %lu %lu\n",tmv.tv_sec,tmv.tv_usec,expected_time);
	uint32_t times=0;
	uint32_t flag=1;
	if (expected_time>0)
	usleep((expected_time-tmv.tv_sec)*1000000-tmv.tv_usec);
	uint32_t interval=10;
	while(1)
	{		nb_rx=rte_eth_rx_burst(portid, 0, &m1[0], 1);
			if (nb_rx==1)
					{
								my_hdr = rte_pktmbuf_mtod_offset(m1[0], struct my_header *, 0);
										flag=my_hdr->filled_index;
												
		for (int i=start;i<=end;i++)
		{
			get_fermat_from_a_switch(2048,i,flag,qid,pools);
			//printf("Success\n");
			//usleep(200);
			total=total+2048;
		}
		rte_pktmbuf_free(m1[0]);
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
	uint32_t lcore_id;
	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	argc -= ret;
	argv += ret;

	/* Check that there is one port to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	/*if (nb_ports != 1)
		rte_exit(EXIT_FAILURE, "Error: number of ports must be one\n");*/

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL1", NUM_MBUFS,
		MBUF_CACHE_SIZE, 0, 9000, rte_socket_id());
	 mbuf_pool1[0]=rte_pktmbuf_pool_create("0", NUM_MBUFS,
                MBUF_CACHE_SIZE, 0, 9000, rte_socket_id());
				mbuf_pool1[1]=rte_pktmbuf_pool_create("1", NUM_MBUFS,
                MBUF_CACHE_SIZE, 0, 9000, rte_socket_id());
	if (mbuf_pool1[0] == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
		if (port_init(portid, mbuf_pool1[0]) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
		scanf("%lu",&expected_time);
rte_eal_mp_remote_launch(lcore_main, NULL, CALL_MASTER);

		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	

	return 0;
}

