#!/bin/bash
#source(ap) ---> destination(mobile) ---> protocol tcp queue 1.
#source(ap) ---> destination(mobile) ---> protocol 201 queue 2.
#destination(ap) ---> source (mobile) --->protocol 202 queue 1. (ack with hashes).

if [ $1 == "bs" ]; then
    iptables -A OUTPUT -p tcp -s 10.10.0.1 -d 10.10.0.6 -j NFQUEUE --queue-num 0
#    iptables -A INPUT -p 202 -s 10.10.0.6 -d 10.10.0.1 -j NFQUEUE --queue-num 1
#    iptables -A FORWARD -p tcp -d 10.10.10.1 -j NFQUEUE --queue-num 1
elif [ $1 == "m" ]; then
    iptables -A INPUT -p 201 -s 10.10.0.1 -d 10.10.0.6 -j NFQUEUE --queue-num 2
    iptables -A INPUT -p 200 -s 10.10.0.1 -d 10.10.0.6 -j NFQUEUE --queue-num 2
#    iptables -A OUTPUT -p tcp -s 10.10.0.6 -d 10.10.0.1 -j NFQUEUE --queue-num 3
elif [ $1 == "c" ]; then
    iptables -F
elif [ $1 == "lo" ]; then
    iptables -A OUTPUT -p tcp -s 127.0.0.1 -d 127.0.0.1 -j NFQUEUE --queue-num 0
    iptables -A INPUT -p 201 -s 127.0.0.1 -d 127.0.0.1 -j NFQUEUE --queue-num 1
    iptables -A INPUT -p 200 -s 127.0.0.1 -d 127.0.0.1 -j NFQUEUE --queue-num 1
    #iptables -A INPUT -p tcp -s 127.0.0.1 -d 127.0.0.1 -j NFQUEUE --queue-num 1
elif [ $1 == "ba" ]; then
    iptables -A OUTPUT -p tcp -s 20.0.0.1 -d 20.0.0.2 -j NFQUEUE --queue-num 0
    iptables -A INPUT -p 202 -s 20.0.0.2 -d 20.0.0.1 -j NFQUEUE --queue-num 1
elif [ $1 == "ma" ]; then
    iptables -A INPUT -p 201 -s 20.0.0.1 -d 20.0.0.2 -j NFQUEUE --queue-num 2
    iptables -A INPUT -p 200 -s 20.0.0.1 -d 20.0.0.2 -j NFQUEUE --queue-num 2
    iptables -A OUTPUT -p tcp -s 20.0.0.2 -d 20.0.0.1 -j NFQUEUE --queue-num 3
fi

iptables -L -n
