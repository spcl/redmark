/**                                                                                                      
 * ReDMArk: Bypassing RDMA Security Mechanisms
 * 
 * Launch a client that will be impersonated.
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
    cxxopts::Options options(argv[0], "A victim client. It will be impersonated.");
    options
      .positional_help("[optional args]")
      .show_positional_help();
 
  try
  {
 
    options.add_options()
      ("a,address", "IP address of the victim", cxxopts::value<std::string>(), "IP")
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

 
  
void print_data(VerbsEP *ep){

  struct ibv_qp_attr attr;
  struct ibv_qp_init_attr init_attr;
  int ret = ibv_query_qp(ep->qp, &attr, IBV_QP_RQ_PSN | IBV_QP_SQ_PSN, &init_attr );
  assert(ret==0 && "ibv_query_qp failed");
  printf("PSNs. receive-PSN: %u send-PSN %u \n", attr.rq_psn, attr.sq_psn);
  printf("QPN %u \n",ep->qp->qp_num);

}


std::vector<VerbsEP *> connections;

int main(int argc, char* argv[]){
 
  auto allparams = parse(argc,argv);

  std::string ip = allparams["address"].as<std::string>();  

  printf("The test sends a message each 60 seconds.");
 

  int port = 9999;
  ClientRDMA * client = new ClientRDMA(const_cast<char*>(ip.c_str()),port);
  struct ibv_qp_init_attr attr;
  struct rdma_conn_param conn_param;
 
  memset(&attr, 0, sizeof(attr));
  attr.cap.max_send_wr = 1;
  attr.cap.max_recv_wr = 1;
  attr.cap.max_send_sge = 1;
  attr.cap.max_recv_sge = 1;
  attr.cap.max_inline_data = 0;
  attr.qp_type = IBV_QPT_RC;

  memset(&conn_param, 0 , sizeof(conn_param));
  conn_param.responder_resources = 0;
  conn_param.initiator_depth =  0;
  conn_param.retry_count = 3;  
  conn_param.rnr_retry_count = 3;  
  
  struct ibv_pd* pd = NULL;

  VerbsEP *ep = client->connectEP(&attr,&conn_param,pd);
  pd = ep->pd;
  
  print_data(ep);
   
  char* ptr = (char*)malloc(4096);
  

  struct ibv_mr * mr = ep->reg_mem(ptr,4096);
  
  print_data(ep);

  ep->send_signaled(1, (uint64_t)mr->addr, mr->lkey, 16);

  struct ibv_wc wc;
  while( ep->poll_send_completion(&wc) == 0){

  }
  printf("A message is sent. Completion status is %d\n",wc.status);

  print_data(ep);
 

  while(true){
    printf("Next print in 5 seconds\n");
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    print_data(ep);
    printf("Next print in 55 seconds. and I will try to send \n");
    std::this_thread::sleep_for(std::chrono::milliseconds(55000));
    print_data(ep);

    ep->send_signaled(1, (uint64_t)mr->addr, mr->lkey, 16);

    struct ibv_wc wc;
    while( ep->poll_send_completion(&wc) == 0){

    }
    printf("A message is sent. Completion status is %d\n",wc.status);
  }
  
  return 0; 
}

 
 
 
