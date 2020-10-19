/**                                                                                                      
 * ReDMArk: Bypassing RDMA Security Mechanisms
 * 
 * Launch a server that will receive packets from the attacker.
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
#include <thread>
#include <arpa/inet.h>

std::vector<VerbsEP *> connections;
 
cxxopts::ParseResult
parse(int argc, char* argv[])
{
    cxxopts::Options options(argv[0], "Server for the QP test. It accepts connections and is the injection target.");
    options
      .positional_help("[optional args]")
      .show_positional_help();
 
  try
  {
 
    options.add_options()
      ("a,address", "IP address", cxxopts::value<std::string>(), "IP")
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


char * myip = NULL;

void print_data(VerbsEP *ep,struct ibv_mr *mr){

  struct ibv_qp_attr attr;
  struct ibv_qp_init_attr init_attr;
  int ret = ibv_query_qp(ep->qp, &attr, IBV_QP_STATE| IBV_QP_RQ_PSN | IBV_QP_SQ_PSN, &init_attr );
  if(ret == 0){
   if(attr.qp_state != 3){
     printf("Connection has been broken\n");
     return;
   }
   struct sockaddr * addr = rdma_get_peer_addr (ep->id);
   in_addr ippp = ((sockaddr_in*)addr)->sin_addr;
   printf("run to hack me: sudo ./spoofv2 16 1 %s %s %u %u %lu %u\n", inet_ntoa(ippp), myip,ep->qp->qp_num, attr.rq_psn, (uint64_t)((char*)mr->addr+1024),mr->rkey);
  }
}



int main(int argc, char* argv[]){
  auto allparams = parse(argc,argv);

  std::string ip = allparams["address"].as<std::string>(); // "192.168.1.20"; .c_str()
  myip = (char*)ip.c_str();

  int port = 9999;

  ServerRDMA * server = new ServerRDMA(const_cast<char*>(ip.c_str()),port);
  struct ibv_qp_init_attr attr;
  struct rdma_conn_param conn_param;
 
 
  memset(&attr, 0, sizeof(attr));
  attr.cap.max_send_wr = 1;
  attr.cap.max_recv_wr = 16;
  attr.cap.max_send_sge = 1;
  attr.cap.max_recv_sge = 1;
  attr.cap.max_inline_data = 0;
  attr.qp_type = IBV_QPT_RC;

  memset(&conn_param, 0 , sizeof(conn_param));
  conn_param.responder_resources = 0;
  conn_param.initiator_depth = 0;
  conn_param.retry_count = 3; // TODO
  conn_param.rnr_retry_count = 3; // TODO 
 
  struct ibv_pd *pd = server->create_pd();
 
  connections.push_back(server->acceptEP(&attr,&conn_param,pd));

  VerbsEP* ep = connections[0];
   
  char* ptr = (char*)malloc(4096);
  memset(ptr,0,4096);
  *(ptr+1024) = 1;
  struct ibv_mr * mr = ep->reg_mem(ptr,4096);
  
  printf("Mem: %lu rkey %u\n",(uint64_t)(ptr+1024),mr->rkey);

  for(uint32_t i = 0; i<16; i++){
   ep->post_recv(i,  mr);
  }
  
  print_data(ep,mr);


  struct ibv_wc wc;
  while(true){
    int ret = ep->poll_recv_completion(&wc);
    if(ret!=0){
      printf("Received message. status: %d. opcode: %d\n",wc.status,wc.opcode);
    }
    if(*(ptr+1024)==0){
      printf("memory is corrupted\n");
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    print_data(ep,mr);

  }
   

  return 0;
}

