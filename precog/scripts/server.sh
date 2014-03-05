
if [ $1 == "start" ]; then
	iptables -F
	bash set_iptables.sh bs
	../pserver/pc_server
elif [ $1 == "stop" ]; then
	kill -9 `pidof pc_server`
	iptables -F
	iptables -L -n
fi
