/**                                                                                                      
 * ReDMArk: Bypassing RDMA Security Mechanisms
 * 
 * Launch a test to show predictability of memory addresses allocated with malloc and mmap. 
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

const size_t PAGE_SIZE = 4096 ;

 
cxxopts::ParseResult
parse(int argc, char* argv[])
{
  cxxopts::Options options(argv[0], "Consecutive Allocation of Memory Regions. See vulnerability (V4). ");
  options.positional_help("[optional args]")
  .show_positional_help();

  try
  {

    options.add_options()
      ("n,num", "number of allocations", cxxopts::value<uint32_t>()->default_value(std::to_string(20)), "N")
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


void print_test(std::vector<char*> &mem){
  

  printf("Allocated addresses: ");
  for(auto &x : mem){
    printf("%p ",x);
  }
  printf("\n");

  std::map<long long,int> hist;
  printf("Address offsets: ");
  for(uint32_t i = 1; i<mem.size(); i++){
    long long diff = (long long)mem[i] - (long long)mem[i-1]  ;
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


void test1(uint32_t size, uint32_t N){
  printf("test1 using mmap call. We allocate twenty buffers of %u bytes in a loop.\n",size);
  std::vector<char*> mem;
  for(uint32_t i=0; i<N; i++){
    char * buf = (char*)mmap(NULL , size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED , -1, 0);
    if(buf == MAP_FAILED){
      perror("mmap failed");
      exit(1);
    }
    mem.push_back(buf);
  }

  print_test(mem);
  // deallocate memory
  for(auto &x : mem){
    munmap(x,size);
  }
}

void test2(uint32_t size, uint32_t N){
  printf("test2 using malloc call. We allocate twenty buffers of %u bytes in a loop.\n",size);
  std::vector<char*> mem;
  for(uint32_t i=0; i<N; i++){
    char * buf = (char*)malloc(size);
    if(buf == MAP_FAILED){
      perror("mmap failed");
      exit(1);
    }
    mem.push_back(buf);
  }

  print_test(mem);

  // deallocate memory
  for(auto &x : mem){
    free(x);
  }
}





int main(int argc, char **argv)
{ 

  auto allparams = parse(argc,argv);
  uint32_t N = allparams["num"].as<uint32_t>();
 
  printf("Pagesize %ld [bytes]\n",PAGE_SIZE);
  
  test1(PAGE_SIZE,N);
  test1(100,N);
  test1(3*PAGE_SIZE + 100,N);

  printf("\n\n");

  test2(PAGE_SIZE,N);
  test2(100,N);
  test2(3*PAGE_SIZE + 100,N);

  return 0;
}

