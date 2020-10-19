/**                                                                                                      
 * ReDMArk: Bypassing RDMA Security Mechanisms
 * 
 * A set of helper functions for working with RDMA.
 *
 * Copyright (c) 2020-2021 ETH-Zurich. All rights reserved.
 * 
 * Author(s): Konstantin Taranov <konstantin.taranov@inf.ethz.ch>
 * 
 */
#pragma once
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <infiniband/verbs.h>

 
class VerbsEP{

public:
  struct ibv_qp * const qp;
  struct ibv_pd * const pd;
  const uint32_t max_inline_data;
 
  const uint32_t max_send_size;
  const uint32_t max_recv_size;

  VerbsEP(struct ibv_qp *qp, uint32_t max_inline_data,uint32_t max_send_size,uint32_t max_recv_size): 
          qp(qp), pd(qp->pd), max_inline_data(0),max_send_size(max_send_size),max_recv_size(max_recv_size)
  {
      // empty
  }

  ~VerbsEP(){
    // empty
  }

  uint32_t get_qp_num() const{
    return qp->qp_num;
  }
 
  struct ibv_mr * reg_mem(void *buf, uint32_t size){
      return ibv_reg_mr(this->pd, buf, size, IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);
  }

  struct ibv_mr * reg_mem_with_atomic(void *buf, uint32_t size){
    return ibv_reg_mr(this->pd, buf, size, IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC);
  }  

  void dereg_mem(struct ibv_mr * mr){
      ibv_dereg_mr(mr);
  }
 
  inline int poll_send_completion(struct ibv_wc* wc, int num = 1){
      return ibv_poll_cq(this->qp->send_cq, num, wc);
  }

  inline int poll_recv_completion(struct ibv_wc* wc, int num = 1){
      return ibv_poll_cq(this->qp->recv_cq, num, wc);
  }

  static inline int post_srq_recv(struct ibv_srq *srq, uint64_t wr_id, uint64_t local_addr=0ULL, uint32_t lkey=0, uint32_t length=0){
    struct ibv_sge sge;

    sge.addr = local_addr;
    sge.length = length;
    sge.lkey = lkey;

    struct ibv_recv_wr wr, *bad;

    wr.wr_id = wr_id;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;

    return ibv_post_srq_recv(srq,&wr, &bad);
  }

  inline int post_recv(uint64_t wr_id, struct ibv_mr * mr){
      return post_recv(wr_id, (uint64_t)mr->addr, mr->lkey,  mr->length);
  }

  inline int post_recv(uint64_t wr_id, uint64_t local_addr=0ULL, uint32_t lkey=0, uint32_t length=0){
    struct ibv_sge sge;

    sge.addr = local_addr;
    sge.length = length;
    sge.lkey = lkey;

    struct ibv_recv_wr wr, *bad;

    wr.wr_id = wr_id;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;

    return ibv_post_recv(qp, &wr, &bad);
  }

  inline int post_recv(struct ibv_recv_wr * wr){
    struct ibv_recv_wr *bad;
    return ibv_post_recv(qp, wr, &bad);
  }

  inline int post_shared_recv(uint64_t wr_id, struct ibv_mr * mr){
      return post_shared_recv(wr_id, (uint64_t)mr->addr, mr->lkey,  mr->length);
  }

  inline int post_shared_recv(uint64_t wr_id, uint64_t local_addr=0ULL, uint32_t lkey=0, uint32_t length=0){
    struct ibv_sge sge;

    sge.addr = local_addr;
    sge.length = length;
    sge.lkey = lkey;

    struct ibv_recv_wr wr, *bad;

    wr.wr_id = wr_id;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;

    return ibv_post_srq_recv(qp->srq, &wr, &bad);
  }

  inline int send_signaled(uint64_t wr_id, uint64_t local_addr, uint32_t lkey, uint32_t length){
    unsigned int send_flags = IBV_SEND_SIGNALED;

    if(length!=0 && length<=max_inline_data){
        send_flags |= IBV_SEND_INLINE;
    }

    return two_sided( IBV_WR_SEND, send_flags, wr_id, 0,local_addr, lkey, length);
  }

  inline int send(uint64_t wr_id, uint64_t local_addr, uint32_t lkey, uint32_t length){
    unsigned int send_flags = 0;

    if(length!=0 && length<=max_inline_data){
        send_flags |= IBV_SEND_INLINE;
    }
    return two_sided( IBV_WR_SEND, send_flags, wr_id, 0,local_addr, lkey, length);
  }


  inline int send_with_imm_signaled(uint64_t wr_id, uint32_t imm_data, uint64_t local_addr, uint32_t lkey, uint32_t length){
    unsigned int send_flags = IBV_SEND_SIGNALED;

    if(length!=0 && length<=max_inline_data){
        send_flags |= IBV_SEND_INLINE;
    }

    return two_sided( IBV_WR_SEND_WITH_IMM, send_flags, wr_id, imm_data,local_addr, lkey, length);
  }

  inline int send_with_imm(uint64_t wr_id, uint32_t imm_data, uint64_t local_addr, uint32_t lkey, uint32_t length){
    unsigned int send_flags = 0;

    if(length!=0 && length<=max_inline_data){
        send_flags |= IBV_SEND_INLINE;
    }
    return two_sided( IBV_WR_SEND_WITH_IMM, send_flags, wr_id, imm_data,local_addr, lkey, length);
  }

  inline int write_signaled(uint64_t wr_id, uint64_t local_addr, uint32_t lkey, uint64_t remote_addr, uint32_t rkey, uint32_t length){

    unsigned int send_flags = IBV_SEND_SIGNALED;

    if(length!=0 && length<=max_inline_data){
        send_flags |= IBV_SEND_INLINE;
    }
    return one_sided(IBV_WR_RDMA_WRITE,send_flags,wr_id,0,local_addr,lkey,remote_addr,rkey,length);
  }


  inline int write(uint64_t wr_id, uint64_t local_addr, uint32_t lkey, uint64_t remote_addr, uint32_t rkey, uint32_t length){

    unsigned int send_flags = 0;

    if(length!=0 && length<=max_inline_data){
        send_flags |= IBV_SEND_INLINE;
    }
    return one_sided(IBV_WR_RDMA_WRITE,send_flags,wr_id,0,local_addr,lkey,remote_addr,rkey,length);
  }

  inline int write_send_signaled(uint64_t wr_id, uint64_t local_addr, uint32_t lkey, uint64_t remote_addr, uint32_t rkey, uint32_t length, uint32_t payload){
      struct ibv_sge sge[2];

  
      sge[0].addr = local_addr;
      sge[0].length = length;
      sge[0].lkey = lkey;
      struct ibv_send_wr wr[2], *bad;

      wr[0].wr_id = wr_id;
      wr[0].next = &wr[1];
      wr[0].sg_list = &sge[0];
      wr[0].num_sge = 1;
      wr[0].opcode = IBV_WR_RDMA_WRITE;

      wr[0].send_flags = (length<=max_inline_data ? IBV_SEND_INLINE : 0);   

      wr[0].wr.rdma.remote_addr = remote_addr;
      wr[0].wr.rdma.rkey        = rkey;

      sge[1].addr = local_addr;
      sge[1].length = payload;
      sge[1].lkey = lkey;

      wr[1].wr_id = wr_id;
      wr[1].next = NULL;
      wr[1].sg_list = &sge[1];
      wr[1].num_sge = 1;
      wr[1].opcode = IBV_WR_SEND;
      wr[1].send_flags = IBV_SEND_SIGNALED | (payload<=max_inline_data ? IBV_SEND_INLINE : 0);   
 
 
      return ibv_post_send(this->qp, wr, &bad);    

  }


    inline int write_write_signaled(uint64_t wr_id, uint64_t local_addr, uint32_t lkey, uint64_t remote_addr, uint32_t rkey, uint32_t length, uint32_t payload){
      struct ibv_sge sge[2];
 
      sge[0].addr = local_addr;
      sge[0].length = length;
      sge[0].lkey = lkey;
      struct ibv_send_wr wr[2], *bad;

      wr[0].wr_id = wr_id;
      wr[0].next = &wr[1];
      wr[0].sg_list = &sge[0];
      wr[0].num_sge = 1;
      wr[0].opcode = IBV_WR_RDMA_WRITE;

      wr[0].send_flags = (length<=max_inline_data ? IBV_SEND_INLINE : 0);   ;   

      wr[0].wr.rdma.remote_addr = remote_addr;
      wr[0].wr.rdma.rkey        = rkey;

      sge[1].addr = local_addr;
      sge[1].length = payload;
      sge[1].lkey = lkey;

      wr[1].wr_id = wr_id;
      wr[1].next = NULL;
      wr[1].sg_list = &sge[1];
      wr[1].num_sge = 1;
      wr[1].opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
      wr[1].send_flags = IBV_SEND_SIGNALED | (payload<=max_inline_data ? IBV_SEND_INLINE : 0);  
 
      wr[1].wr.rdma.remote_addr = remote_addr;
      wr[1].wr.rdma.rkey        = rkey; 
      return ibv_post_send(this->qp, wr, &bad);    
  }

  inline int send_cas_signaled(uint64_t wr_id, uint64_t local_addr, uint32_t lkey, uint64_t remote_addr, uint32_t rkey, uint64_t expected, uint64_t swap ){
 
    struct ibv_sge sge;

    sge.addr = local_addr;
    sge.length = 8;
    sge.lkey = lkey;
    struct ibv_send_wr wr, *bad;

    wr.wr_id = wr_id;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_ATOMIC_CMP_AND_SWP;

    wr.send_flags = IBV_SEND_SIGNALED ;   //| IBV_SEND_INLINE
  
    wr.wr.atomic.remote_addr = remote_addr;
    wr.wr.atomic.rkey        = rkey;
    wr.wr.atomic.compare_add = expected; /* expected value in remote address */
    wr.wr.atomic.swap        = swap; /* the value that remote address will be assigned to */
 
    return ibv_post_send(this->qp, &wr, &bad);    
 
  }

  inline int write_with_imm_signaled(uint64_t wr_id, uint32_t imm_data, 
      uint64_t local_addr, uint32_t lkey, uint64_t remote_addr, uint32_t rkey, uint32_t length){

    unsigned int send_flags = IBV_SEND_SIGNALED;

    if(length!=0 && length<=max_inline_data){
        send_flags |= IBV_SEND_INLINE;
    }
    return one_sided(IBV_WR_RDMA_WRITE_WITH_IMM,send_flags,wr_id,imm_data,local_addr,lkey,remote_addr,rkey,length);
  }


  inline int write_with_imm(uint64_t wr_id, uint32_t imm_data, 
      uint64_t local_addr, uint32_t lkey, uint64_t remote_addr, uint32_t rkey, uint32_t length){

    unsigned int send_flags = 0;

    if(length!=0 && length<=max_inline_data){
        send_flags |= IBV_SEND_INLINE;
    }
    return one_sided(IBV_WR_RDMA_WRITE_WITH_IMM,send_flags,wr_id,imm_data,local_addr,lkey,remote_addr,rkey,length);
  }


  inline int read_signaled(uint64_t wr_id, uint64_t local_addr, uint32_t lkey, uint64_t remote_addr, 
                           uint32_t rkey, uint32_t length)
  {
    unsigned int send_flags = IBV_SEND_SIGNALED;
 
    return one_sided(IBV_WR_RDMA_READ,send_flags,wr_id,0,local_addr,lkey,remote_addr,rkey,length);
  }

  inline int read(uint64_t wr_id, uint64_t local_addr, uint32_t lkey, uint64_t remote_addr, uint32_t rkey, uint32_t length)
  {
    unsigned int send_flags = 0;

    return one_sided(IBV_WR_RDMA_READ,send_flags,wr_id,0,local_addr,lkey,remote_addr,rkey,length);
  }


  inline int one_sided(enum ibv_wr_opcode opcode, unsigned int send_flags, uint64_t wr_id, uint32_t imm_data, 
    uint64_t local_addr, uint32_t lkey, uint64_t remote_addr, uint32_t rkey, uint32_t length)
  {
      struct ibv_sge sge;

      sge.addr = local_addr;
      sge.length = length;
      sge.lkey = lkey;
      struct ibv_send_wr wr, *bad;

      wr.wr_id = wr_id;
      wr.next = NULL;
      wr.sg_list = &sge;
      wr.num_sge = 1;
      wr.opcode = opcode;

      wr.send_flags = send_flags;   
      wr.imm_data = imm_data;


      wr.wr.rdma.remote_addr = remote_addr;
      wr.wr.rdma.rkey        = rkey;

      return ibv_post_send(this->qp, &wr, &bad);    
  }


  inline int two_sided(enum ibv_wr_opcode opcode, unsigned int send_flags, uint64_t wr_id, uint32_t imm_data, 
    uint64_t local_addr, uint32_t lkey, uint32_t length)
  {
      struct ibv_sge sge;

      sge.addr = local_addr;
      sge.length = length;
      sge.lkey = lkey ;
      struct ibv_send_wr wr, *bad;

      wr.wr_id = wr_id;
      wr.next = NULL;
      wr.sg_list = &sge;
      wr.num_sge = 1;
      wr.opcode = opcode;

      wr.send_flags = send_flags;  
      wr.imm_data = imm_data; 

      return ibv_post_send(this->qp, &wr, &bad);
  }
 
  inline int post_send(struct ibv_send_wr *wr)
  {
      struct ibv_send_wr *bad;
      return ibv_post_send(this->qp, wr, &bad);
  }
 

};
