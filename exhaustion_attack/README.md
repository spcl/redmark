# (A5) Performance Degradation using Resource Exhaustion

The attack shows that attackers can silently degrade performance of a victim RDMA service. 


## Requirements
 * GCC >= 4.9 with C++11 features
 * rdma-core library, or equivalent RDMA verbs library 
 * RDMA-capable network devices must have assigned IP addresses

## Usage 

To compile the code simply run `make`. 

To perform an attack, the victim service should be launched using `./victim -a <IP> -c <CONNECTIONS>`, where `<IP>` is the IP address of the victim, and `<CONNECTIONS>` is the total number of connections the victim should accept. `<CONNECTIONS>` should be equal to the number of attackers plus one.
Then the attackers will connect to the victim and will flood the victim service with one-sided RDMA requests. 
To run an attacker use `./attacker -a <IP>`, where `<IP>` is the IP address of the victim. By default, attackers use RDMA read requests for the attack. Use the flag `--write` to use RDMA writes for exhausting processing resources of the victim's RNIC.

The performance measurements are made by a client that connects to the victim. By default, the client measures performance of RDMA reads. Use the flag `--write` to measure performance of RDMA writes. 


Basic usage example
```
make
./victim -a 192.168.1.10 -c 2
./attacker -a 192.168.1.10 --write
./client -a 192.168.1.10 
```

For more arguments call
```
make
./victim --help
./attacker --help
./client --help
```


## Scripts
Note, to run the script, we require manually edit `run_test.sh` to specify the IP addresses of the RDMA devices in the cluster.
To run all experiments used in the paper, one can use `run_all.sh` script, which calls `run_test.sh`. 
Too see the usage of `run_test.sh` script, you can execute `run_test.sh --help`. 

The `run_test.sh` script contains hard-coded IP addresses of the cluster machines. The script assumes that the IP addresses of the machines grow linearly. You need to specify only the IP address of a single machine and the script will increment the provided IP address to launch processes on different machines. The script launches a victim service at the provided IP address, then it starts the requested number of attackers at the subsequent IP addresses. The client is always launched locally, i.e., at the same machine where the script is launched. 

For example, if a test involves 3 attackers, and the provided IP address is 192.168.1.10, the processes will be launched at:
```
192.168.1.10 -> victim service
192.168.1.11 -> an attacker
192.168.1.12 -> an attacker
192.168.1.13 -> an attacker
local ip -> a client 
```

For correct measurements, the scripts should be launched on an RDMA-capable machine that is different from the victim and the attackers.





