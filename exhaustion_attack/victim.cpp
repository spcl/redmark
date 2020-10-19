/**                                                                                                      
 * ReDMArk: Bypassing RDMA Security Mechanisms
 * 
 * Launch a victim service for resource exhaustion attack.
 *
 * Copyright (c) 2020-2021 ETH-Zurich. All rights reserved.
 * 
 * Author(s): Konstantin Taranov <konstantin.taranov@inf.ethz.ch>
 * 
 */
#include "verbsEP.hpp"
#include "connectRDMA.hpp"
#include "cxxopts.hpp"
#include <vector>

uint32_t totalsize;
  
struct ibv_mr *mr;

std::vector<VerbsEP *> connections;
std::vector<struct ibv_mr*> regions;


void server_func(){

  struct ibv_wc wc[8];
  while(true){
    int ret = connections[0]->poll_recv_completion(wc,1);
    if(ret){
      // we ignore events as the attack does not require it.
      printf("Received a completion event\n");
    }
  }
}

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
      ("a,address", "IP address", cxxopts::value<std::string>(), "IP")
      ("len", "Buffer size", cxxopts::value<uint32_t>()->default_value(std::to_string(2048)), "N")
      ("reads", "RDMA read caps", cxxopts::value<uint32_t>()->default_value(std::to_string(64)), "N")
      ("c,connections", "The numder of connections for the test", cxxopts::value<uint32_t>()->default_value(std::to_string(1)), "N")
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



int main(int argc, char* argv[]){
  auto allparams = parse(argc,argv);

  std::string ip = allparams["address"].as<std::string>(); // "192.168.1.20"; .c_str()
  totalsize = allparams["len"].as<uint32_t>();

  int port = 9999;

  ServerRDMA * server = new ServerRDMA(const_cast<char*>(ip.c_str()),port);
  struct ibv_qp_init_attr attr;
  struct rdma_conn_param conn_param;
 
  uint32_t reads = allparams["reads"].as<uint32_t>();;

  uint32_t recv_size = 1000;


  memset(&attr, 0, sizeof(attr));
  attr.cap.max_send_wr = 16;
  attr.cap.max_recv_wr = recv_size;
  attr.cap.max_send_sge = 1;
  attr.cap.max_recv_sge = 1;
  attr.cap.max_inline_data = 0;
  attr.qp_type = IBV_QPT_RC;

  memset(&conn_param, 0 , sizeof(conn_param));
  conn_param.responder_resources = reads;
  conn_param.initiator_depth = 0;
  conn_param.retry_count = 3; // TODO
  conn_param.rnr_retry_count = 3; // TODO 


  struct ibv_pd *pd = server->create_pd();
 
  connections.push_back(server->acceptEP(&attr,&conn_param,pd));

  uint32_t cons = allparams["connections"].as<uint32_t>();

  if(cons>1){
    attr.cap.max_recv_wr = 1;
    attr.send_cq = connections[0]->qp->send_cq;
    attr.recv_cq = connections[0]->qp->recv_cq;
    
    for(uint32_t i=1; i < cons; i++){
      connections.push_back(server->acceptEP(&attr,&conn_param,pd));
    }

  }
 
  printf("All connections are established\n");
  for(uint32_t i=0; i < cons; i++){
    char* buf = (char*)aligned_alloc(4096, totalsize); // 8MiB
    mr =  connections[0]->reg_mem(buf,totalsize);
    regions.push_back(mr);
  }
 
  for(uint32_t i=0; i < connections.size(); i++){
      struct ibv_sge sge;
      sge.addr=(uint64_t)regions[i]->addr;
      sge.lkey=regions[i]->rkey;
      sge.length=totalsize;
      memcpy((void*)sge.addr, &sge,sizeof(sge));
      connections[i]->send_signaled(0,sge.addr, sge.lkey, sizeof(sge));
  }

  int expect = cons; 
  struct ibv_wc wc;
  while(expect != 0){
     int ret = connections[0]->poll_send_completion(&wc);
     if(ret > 0) expect -= ret;
  }

  server_func();

  return 0;
}

