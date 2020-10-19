# (V1) Memory Protection Key Randomness


The test prints rkeys of memory regions for various allocation/deallocation scenarios.


## Requirements
 * GCC >= 4.9 with C++11 features
 * rdma-core library, or equivalent RDMA verbs library 

## Usage 

Basic usage example
```
make
./main --help
```

# (V2) Static Initialization State for Key Generation

The same tool can be used to print rkeys after a reboot.



# (V3) Shared Key Generator 

Two instances of the tool can be run simultaneously to see the correlation between generated keys. 