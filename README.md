# ReDMArk: Bypassing RDMA Security Mechanisms.
A framework for security analysis of RDMA networking.
This is the source code for our [USENIX Security paper](paper/redmark.pdf).

## Discovered vulnerabilities
 * (V1) Memory Protection Key Randomness. See [`rkey_tests/`](rkey_tests/).
 * (V2) Static Initialization State for Key Generation. See [`rkey_tests/`](rkey_tests/).
 * (V3) Shared Key Generator. See [`rkey_tests/`](rkey_tests/).
 * (V4) Consecutive Allocation of Memory Regions. See [`allocation_addr_tests/`](allocation_addr_tests/).
 * (V5) Linearly Increasing QP Numbers. See [`qp_tests/`](qp_tests/).
 * (V6) Fixed Starting Packet Sequence Number. See [USENIX Security paper](paper/redmark.pdf).
 * (V7) Limited Attack Detection Capabilities. See [USENIX Security paper](paper/redmark.pdf). 
 * (V8) Missing Encryption and Authentication in RDMA Protocols. See [USENIX Security paper](paper/redmark.pdf).
 * (V9) Single Protection Domain for all QPs. See [USENIX Security paper](paper/redmark.pdf). 
 * (V10) Implicit On-Demand Paging (ODP). See [USENIX Security paper](paper/redmark.pdf). 

## Implemented attacks
 * (A1) Packet Injection using Impersonation. See [`inject_attack/`](inject_attack/).
 * (A2) DoS Attack by Transiting QPs to an Error State. See [`inject_attack/`](inject_attack/).
 * (A3) Unauthorized Memory Access. See [USENIX Security paper](paper/redmark.pdf). 
 * (A4) DoS Attack based on Queue Pair Allocation Resource Exhaustion. See [`qp_tests/`](qp_tests/).
 * (A5) Performance Degradation using Resource Exhaustion. See [`exhaustion_attack/`](exhaustion_attack/).
 * (A6) Facilitating Attacks using RDMA. See [`preload_attack/`](preload_attack/).

## Citing this work

If you use our code, please consider citing our [USENIX Security paper](paper/redmark.pdf):

```
@inproceedings{rot2021redmark,
  title={{ReDMArk}: Bypassing {RDMA} Security Mechanisms},
  author={Benjamin Rothenberger and Konstantin Taranov and Adrian Perrig and Torsten Hoefler},
  booktitle={{USENIX} Security Symposium ({USENIX} Security 21)},
  year={2021},
}
```

## Contact 
Konstantin Taranov (konstantin.taranov "at" inf.ethz.ch)    
Benjamin Rothenberger (benjamin.rothenberger "at" inf.ethz.ch)  


