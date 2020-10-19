# (V5) Linearly Increasing QP Numbers


The test shows that subsequent QP allocation calls return consecutive QP numbers.


## Requirements
 * GCC >= 4.9 with C++11 features
 * rdma-core library, or equivalent RDMA verbs library 

## Usage 

Basic usage example
```
make
./main --help
```

# (A4) DoS Attack based on Queue Pair Allocation Resource Exhaustion
To find the limit on the number of allocated QPs. Run the following command:

```
make
./main --exhaust
```