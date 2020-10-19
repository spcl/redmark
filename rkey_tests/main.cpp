/**                                                                                                      
 * ReDMArk: Bypassing RDMA Security Mechanisms
 * 
 * Launch a test to show predictability of rkey's of subsequent memory registrations. 
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
#include <iostream>
#include <string>
#include "cxxopts.hpp"

const size_t PAGE_SIZE = 4096 ;

char* page;


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


void test_rereg(struct ibv_pd *pd, uint32_t N){
    // register our userspace buffer with the HCA
  uint32_t firstkey = 0;
  printf("[Test0] We register and immediately deregister the same buffer with remote access.\nRkeys: \n");
  for(uint32_t i=0; i< N; i++){
    struct ibv_mr *mr = ibv_reg_mr(pd, page, PAGE_SIZE, IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);
    if (mr == NULL) {
      fprintf(stderr, "failed to register memory region\n");
      exit(1);
    }

    if(i!=0 && firstkey == mr->rkey){
      printf("\nThe key was repeated after %u registrations\n",i);
      return;
    }

    if(firstkey==0){
      firstkey = mr->rkey;
    }

    printf("0x%X ",mr->rkey);
    int ret = ibv_dereg_mr(mr);
    if (ret!=0) {
      fprintf(stderr, "failed to de-register memory region\n");
      exit(1);
    }
  }
  printf("\n");
}


void test_rereg1(struct ibv_pd *pd, uint32_t N){
    // register our userspace buffer with the HCA
  uint32_t firstkey = 0;
  printf("[Test1] We register and immediately deregister different buffers with remote access.\nRkeys: \n");
  for(uint32_t i=0; i< N; i++){

    char * buf = (char*)mmap(NULL , PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED , -1, 0);
    if(buf == MAP_FAILED){
      perror("mmap failed");
      exit(1);
    }

    struct ibv_mr *mr = ibv_reg_mr(pd, buf, PAGE_SIZE, IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);
    if (mr == NULL) {
      fprintf(stderr, "failed to register memory region\n");
      exit(1);
    }

    if(i!=0 && firstkey == mr->rkey){
      printf("\nThe key was repeated after %u registrations\n",i);
      return;
    }

    if(firstkey==0){
      firstkey = mr->rkey;
    }

    printf("0x%X ",mr->rkey);
    int ret = ibv_dereg_mr(mr);
    if (ret!=0) {
      fprintf(stderr, "failed to de-register memory region\n");
      exit(1);
    }
    munmap(buf,PAGE_SIZE);
  }
  printf("\n");
}


void test_rereg2(struct ibv_pd *pd, uint32_t N){
    // register our userspace buffer with the HCA
  uint32_t firstkey = 0;
  printf("[Test2] We register and immediately deregister the same buffer with local access.\nRkeys: \n");
  for(uint32_t i=0; i< N; i++){
    struct ibv_mr *mr = ibv_reg_mr(pd, page, PAGE_SIZE, IBV_ACCESS_LOCAL_WRITE);
    if (mr == NULL) {
      fprintf(stderr, "failed to register memory region\n");
      exit(1);
    }

    if(i!=0 && firstkey == mr->rkey){
      printf("\nThe key was repeated after %u registrations\n",i);
      return;
    }

    if(firstkey==0){
      firstkey = mr->rkey;
    }

    printf("0x%X ",mr->rkey);
    int ret = ibv_dereg_mr(mr);
    if (ret!=0) {
      fprintf(stderr, "failed to de-register memory region\n");
      exit(1);
    }
  }
  printf("\n");
}


void test_rereg3(struct ibv_pd *pd, uint32_t N){
    // register our userspace buffer with the HCA
  uint32_t firstkey = 0;
  printf("[Test3] We register the same buffer with remote access.\nRkeys: \n");
  std::list<struct ibv_mr *> v;

  for(uint32_t i=0; i< N; i++){
    struct ibv_mr *mr = ibv_reg_mr(pd, page, PAGE_SIZE,  IBV_ACCESS_REMOTE_WRITE| IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);
    if (mr == NULL) {
      fprintf(stderr, "failed to register memory region\n");
      exit(1);
    }
    v.push_back(mr);

    if(i!=0 && firstkey == mr->rkey){
      printf("\nThe key was repeated after %u registrations\n",i);
      return;
    }

    if(firstkey==0){
      firstkey = mr->rkey;
    }

    printf("0x%X ",mr->rkey);
  }
  printf("\n");

  for (auto x : v){
    int ret = ibv_dereg_mr(x);
    if (ret!=0) {
      fprintf(stderr, "failed to de-register memory region\n");
      exit(1);
    }
  }
}



void test_rereg4(struct ibv_pd *pd, uint32_t N){
    // register our userspace buffer with the HCA
  uint32_t firstkey = 0;
  printf("[Test4] We register the same buffer with local access.\nRkeys: \n");
  std::list<struct ibv_mr *> v;

  for(uint32_t i=0; i< N; i++){
    char * buf = (char*)mmap(NULL , PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED , -1, 0);
    if(buf == MAP_FAILED){
      perror("mmap failed");
      exit(1);
    }

    struct ibv_mr *mr = ibv_reg_mr(pd, buf, PAGE_SIZE, IBV_ACCESS_LOCAL_WRITE);
    if (mr == NULL) {
      fprintf(stderr, "failed to register memory region\n");
      exit(1);
    }
    v.push_back(mr);

    if(i!=0 && firstkey == mr->rkey){
      printf("\nThe key was repeated after %u registrations\n",i);
      return;
    }

    if(firstkey==0){
      firstkey = mr->rkey;
    }

    printf("0x%X ",mr->rkey);
  }
  printf("\n");

  for (auto x : v){
    char* buf = (char*)x->addr;
    int ret = ibv_dereg_mr(x);
    if (ret!=0) {
      fprintf(stderr, "failed to de-register memory region\n");
      exit(1);
    }
    munmap(buf,PAGE_SIZE);
  }
}

void test_rereg5(struct ibv_pd *pd, uint32_t N){
    // register our userspace buffer with the HCA
  uint32_t firstkey = 0;
  printf("[Test5] We register five times the same buffer with remote access, and then deregister the oldest registration.\nRkeys: \n");
  std::list<struct ibv_mr *> v;

  for(uint32_t i=0; i< N; i++){
    struct ibv_mr *mr = ibv_reg_mr(pd, page, PAGE_SIZE, IBV_ACCESS_LOCAL_WRITE);
    if (mr == NULL) {
      fprintf(stderr, "failed to register memory region\n");
      exit(1);
    }

    if(i!=0 && firstkey == mr->rkey){
      printf("\nThe key was repeated after %u registrations\n",i);
      return;
    }

    if(firstkey==0){
      firstkey = mr->rkey;
    }

    printf("0x%X ",mr->rkey);
    if(i>0 && i%5==0){
      int ret = ibv_dereg_mr(v.front());
      if (ret!=0) {
        fprintf(stderr, "failed to de-register memory region\n");
        exit(1);
      }
      v.pop_front();
      v.push_back(mr);
    } else {
      v.push_back(mr);
    }

  }
  printf("\n");

  for (auto x : v){
    int ret = ibv_dereg_mr(x);
    if (ret!=0) {
      fprintf(stderr, "failed to de-register memory region\n");
      exit(1);
    }
  }
}



void test_rereg6(struct ibv_pd *pd, uint32_t N){
    // register our userspace buffer with the HCA
  uint32_t firstkey = 0;
  printf("[Test6] We register two times the same buffer with local access, and then deregister the latest registration.\nRkeys: \n");
  std::list<struct ibv_mr *> v;

  for(uint32_t i=0; i< N; i++){
    struct ibv_mr *mr = ibv_reg_mr(pd, page, PAGE_SIZE, IBV_ACCESS_LOCAL_WRITE);
    if (mr == NULL) {
      fprintf(stderr, "failed to register memory region\n");
      exit(1);
    }

    if(i!=0 && firstkey == mr->rkey){
      printf("\nThe key was repeated after %u registrations\n",i);
      return;
    }

    if(firstkey==0){
      firstkey = mr->rkey;
    }

    printf("0x%X ",mr->rkey);
    if(i>0 && i%2==0){
      int ret = ibv_dereg_mr(mr);
      if (ret!=0) {
        fprintf(stderr, "failed to de-register memory region\n");
        exit(1);
      }
    } else {
      v.push_back(mr);
    }

  }
  printf("\n");

  for (auto x : v){
    int ret = ibv_dereg_mr(x);
    if (ret!=0) {
      fprintf(stderr, "failed to de-register memory region\n");
      exit(1);
    }
  }
}


void test_rereg7(struct ibv_pd *pd, uint32_t N){
    // register our userspace buffer with the HCA
  uint32_t firstkey = 0;
  printf("[Test7] We register five times the same buffer with local access, and then deregister two latest registrations.\nRkeys: \n");
  std::list<struct ibv_mr *> v;

  for(uint32_t i=0; i< N; i++){
    struct ibv_mr *mr = ibv_reg_mr(pd, page, PAGE_SIZE, IBV_ACCESS_LOCAL_WRITE);
    if (mr == NULL) {
      fprintf(stderr, "failed to register memory region\n");
      exit(1);
    }

    if(i!=0 && firstkey == mr->rkey){
      printf("\nThe key was repeated after %u registrations\n",i);
      return;
    }

    if(firstkey==0){
      firstkey = mr->rkey;
    }

    printf("0x%X ",mr->rkey);
    if(i>0 && i%5==0){
      int ret = ibv_dereg_mr(v.front());
      if (ret!=0) {
        fprintf(stderr, "failed to de-register memory region\n");
        exit(1);
      }
      v.pop_front();
      ret = ibv_dereg_mr(v.front());
      if (ret!=0) {
        fprintf(stderr, "failed to de-register memory region\n");
        exit(1);
      }
      v.pop_front();

      v.push_back(mr);
    } else {
      v.push_back(mr);
    }

  }
  printf("\n");

  for (auto x : v){
    int ret = ibv_dereg_mr(x);
    if (ret!=0) {
      fprintf(stderr, "failed to de-register memory region\n");
      exit(1);
    }
  }
}




#ifdef IBV_MW_TYPE_1
void test_mw1(struct ibv_context *ctxt,struct ibv_pd *pd, uint32_t N){

  struct ibv_mr *mr = ibv_reg_mr(pd, page, PAGE_SIZE, IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);
  if (mr == NULL) {
    fprintf(stderr, "failed to register memory region\n");
    exit(1);
  }
  printf("0x%X \n",mr->rkey);
  struct ibv_mw *mw = ibv_alloc_mw(pd,IBV_MW_TYPE_1);
  if(mw==NULL){
    printf("Cannot register mw\n");
    return;
  }

  printf("0x%X \n",mw->rkey);
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

  struct ibv_qp *qp = ibv_create_qp(pd, &qpia);

  struct ibv_mw_bind mw_bind;
  memset(&mw_bind, 0, sizeof(mw_bind));
  mw_bind.wr_id = 1;
  mw_bind.send_flags = IBV_SEND_SIGNALED;
  mw_bind.bind_info.mr = mr;
  mw_bind.bind_info.addr = (uint64_t)page;
  mw_bind.bind_info.length = PAGE_SIZE;
  mw_bind.bind_info.mw_access_flags = IBV_ACCESS_REMOTE_WRITE;


  int ret = ibv_bind_mw(qp, mw, &mw_bind );
  if(ret == 0){
    printf("bind success\n");
    printf("0x%X \n",mw->rkey);

  }

}

void test_mw2(struct ibv_context *ctxt,struct ibv_pd *pd, uint32_t N){

  struct ibv_mr *mr = ibv_reg_mr(pd, page, PAGE_SIZE, IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);
  if (mr == NULL) {
    fprintf(stderr, "failed to register memory region\n");
    exit(1);
  }
  printf("0x%X \n",mr->rkey);
  struct ibv_mw *mw = ibv_alloc_mw(pd,IBV_MW_TYPE_2);
  if(mw==NULL){
    printf("Cannot register mw\n");
    return;
  }

  printf("0x%X \n",mw->rkey);
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

  struct ibv_qp *qp = ibv_create_qp(pd, &qpia);


  ibv_send_wr wr;
  memset(&wr, 0, sizeof(wr));
  wr.wr_id = 1;
  wr.opcode = IBV_WR_BIND_MW;
  wr.bind_mw.mw = mw;
  wr.bind_mw.rkey = ibv_inc_rkey(mw->rkey);
  wr.bind_mw.bind_info.mr = mr;
  wr.bind_mw.bind_info.addr = (uint64_t)page;
  wr.bind_mw.bind_info.length = PAGE_SIZE;
  wr.bind_mw.bind_info.mw_access_flags = IBV_ACCESS_REMOTE_WRITE;
  ibv_send_wr* badwr;

  int ret = ibv_post_send(qp,&wr,&badwr);
  if(ret == 0){
    printf("bind success\n");
    printf("0x%X \n",mw->rkey);

  }
}
#endif

 

cxxopts::ParseResult
parse(int argc, char* argv[])
{
  cxxopts::Options options(argv[0], "Simple Secure QP client");
  options.positional_help("[optional args]")
  .show_positional_help();


  try
  {

    options.add_options()
      ("m,mem", "number of memory registrations", cxxopts::value<uint32_t>()->default_value("10"), "N")
      ("d,dev", "ib device", cxxopts::value<std::string>(), "name")      
      ("h,help", "Print help")
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

int main(int argc, char **argv)
{

  auto allparams = parse(argc,argv);

  uint32_t memnum = allparams["mem"].as<uint32_t>();
 
  struct ibv_device *dev = NULL;
  printf("Pagesize %ld [bytes]\n",PAGE_SIZE);

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

  // allocate a protection domain for our memory region
  struct ibv_pd *pd = ibv_alloc_pd(ctxt);
  if (pd == NULL) {
    fprintf(stderr, "failed to allocate infiniband pd\n");
    exit(1);
  }

  char * buf = (char*)mmap(NULL , PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED , -1, 0);
  if(buf == MAP_FAILED){
    perror("mmap failed");
    exit(1);
  }
  page = buf;


  test_rereg(pd,memnum);
  test_rereg1(pd,memnum);
  test_rereg2(pd,memnum);
  test_rereg3(pd,memnum);
  test_rereg4(pd,memnum);
  test_rereg5(pd,memnum);
  test_rereg6(pd,memnum);
  test_rereg7(pd,memnum);

 // test_mw1(ctxt,pd,1);
 // test_mw2(ctxt,pd,1);

  return 0;
}
