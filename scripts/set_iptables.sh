#!/bin/bash
#source(ap) ---> destination(mobile) ---> protocol tcp queue 1.
#source(ap) ---> destination(mobile) ---> protocol 201 queue 2.
#destination(ap) ---> source (mobile) --->protocol 202 queue 1. (ack with hashes).

if [ $1 == "bs" ]; then
    sudo iptables -A OUTPUT -p tcp -s 10.0.0.1 -d 10.0.0.2 -j NFQUEUE --queue-num 0
#    sudo iptables -A FORWARD -p tcp -d 10.10.10.1 -j NFQUEUE --queue-num 1
elif [ $1 == "m" ]; then
    sudo iptables -A INPUT -p 201 -s 10.0.0.1 -d 10.0.0.2 -j NFQUEUE --queue-num 1
    sudo iptables -A INPUT -p 200 -s 10.0.0.1 -d 10.0.0.2 -j NFQUEUE --queue-num 1
elif [ $1 == "c" ]; then
    sudo iptables -F
elif [ $1 == "lo" ]; then
    sudo iptables -A OUTPUT -p tcp -s 127.0.0.1 -d 127.0.0.1 -j NFQUEUE --queue-num 0
    sudo iptables -A INPUT -p 201 -s 127.0.0.1 -d 127.0.0.1 -j NFQUEUE --queue-num 1
    sudo iptables -A INPUT -p 200 -s 127.0.0.1 -d 127.0.0.1 -j NFQUEUE --queue-num 1
    #sudo iptables -A INPUT -p tcp -s 127.0.0.1 -d 127.0.0.1 -j NFQUEUE --queue-num 1
fi

sudo iptables -L -n
