#!/bin/bash

trap 'echo -ne "Stop tests...\n" && exit 1' INT

min_power=4
max_power=12

for (( a=0; a<=8; a++ ))
do

for (( i=$min_power; i<=$max_power; i++ ))
do
    size=$((2**$i))
    # wa - write attackers. Attackers use RDMA writes
    # ra - read attackers. Attackers use RDMA reads
    # rc - read client. The client evaluates performance of RDMA reads
    # rw = read attacker. The client evaluates performance of RDMA writes
    # Each attacker issues packets of 1024 bytes
./run_test.sh --attackers=$a --writeattack --size=$size --outstand=16 > test1024_wa_rc_${a}_${size}.txt 
./run_test.sh --attackers=$a --outstandattack=16 --size=$size --outstand=16 > test1024_ra_rc_${a}_${size}.txt
./run_test.sh --attackers=$a --writeattack --size=$size --outstand=120 --writeclient> test1024_wa_wc_${a}_${size}.txt
./run_test.sh --attackers=$a --outstandattack=16 --size=$size --outstand=120 --writeclient> test1024_ra_wc_${a}_${size}.txt

echo "done: number of attackers=$a and the size of a request issued by a client=$size"
done

done
