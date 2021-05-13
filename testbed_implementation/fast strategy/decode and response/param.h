#define switch_num 10
#define port_per_switch 4
#define entry_num 512
#define carry_num 512
#define array_num 2
#define PRIME 0x7fffffff // 2**31-1

struct  __attribute__((__packed__)) my_header
{
  uint8_t ethdstAddr[6];
  uint8_t ethsrcAddr[6];
   uint16_t ethtype;
  uint32_t ip_src_addr;
	uint32_t ip_dst_addr;
    uint16_t filled_index;
	uint32_t fermat21[5];
  uint32_t fermat22[5];
  uint32_t fermat01[5];
  uint32_t fermat02[5];
  uint32_t fermat11[5];
  uint32_t fermat12[5];
};

struct fermat
{
    uint32_t ipsrc;
    uint32_t ipdst;
    uint32_t sdport;
    uint32_t rest;
    uint32_t counter;
    //uint32_t filled[5];
};

struct Flow {
    uint32_t counter;
    uint32_t ipsrc;
    uint32_t ipdst;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t errorcode;
};

struct lossResult {
    struct Flow f[entry_num];
    int loss_num;
};

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
  struct recoverFlow rF[entry_num/4];
};