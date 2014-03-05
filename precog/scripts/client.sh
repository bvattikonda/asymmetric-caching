
if [ $1 == "start" ]; then
	iptables -F
	sh set_iptables.sh m
	./pc_client
elif [ $1 == "stop" ]; then
	kill -9 `pidof pc_client`
	iptables -F
	iptables -L -n
fi
