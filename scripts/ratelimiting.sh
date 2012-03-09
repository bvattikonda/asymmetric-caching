#!/bin/bash

userfile=$1

while read line
    do
        rate_limit=$line
        top -b -d 1 > top_$userfile"_"$rate_limit.top&
        if [ $rate_limit -lt 5 ]
        then
            rate_limit=5
        fi
        echo "tc qdisc add dev ath3 root handle 1: cbq avpkt 1000 bandwidth 10mbit"
        tc qdisc add dev ath3 root handle 1: cbq avpkt 1000 bandwidth 10mbit
        echo "tc class add dev ath3 parent 1: classid 1:1 cbq rate '$rate_limit'kbit allot 1500 prio 5 bounded isolated"
        tc class add dev ath3 parent 1: classid 1:1 cbq rate $rate_limit"kbit" allot 1500 prio 5 bounded isolated
        echo "tc filter add dev ath3 parent 1: protocol ip u32 match ip dst 20.0.0.2 flowid 1:1"
        tc filter add dev ath3 parent 1: protocol ip u32 match ip dst 20.0.0.2 flowid 1:1
        echo "tc qdisc add dev ath3 parent 1:1 sfq perturb 10"
        tc qdisc add dev ath3 parent 1:1 sfq perturb 10
        echo "Running experiment for $user_file $rate_limit"
        iperf -c 20.0.0.2 -i 1
        pkill top
        tc qdisc del dev ath3 root
    done < $userfile
