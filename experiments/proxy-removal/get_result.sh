#!/bin/bash

TIMEOUT=1
HOSTNAME=`hostname`
TIME=`date "+%Y%m%d_%H%M%S"`

USER=`whoami`
REXEC="expect -re \"(#|\\\\$) $\"; send \""
REXEC_END="expect -re \"(#|\\\\$) $\""

EVALDIR=/u/ronaldof/udysco/experiments/proxy-removal
REMOTEDIR=/root/removal/results

source $EVALDIR/config.sh

if [ $# -ne 1 ]; then
        echo "$0 <proxy|clients|servers>"
        exit 1
fi

remote_exec() {
        expect -c "
                spawn ssh $1
                $2
                expect -re \"(#|\\\\$) $\" ;  send \"exit\r\"
                interact
        "
}

get_proxy_files() {
        #$REXEC killall pidstat\n\"
	#$REXEC killall tcp_proxy\n\"
                
	remote_exec $PROXY1 "
		$REXEC mkdir -p $REMOTEDIR/old\n\"
                $REXEC mv $REMOTEDIR/cpu_proxy_*.txt $REMOTEDIR/old\n\"
                $REXEC exit\n\"
        "
	rm $EVALDIR/results/cpu_proxy_?.txt
        scp $PROXY1:$REMOTEDIR/old/cpu_proxy_*.txt $EVALDIR/results/
}

get_clients_files() {
	remote_exec $CLIENT1 "
		$REXEC mkdir -p $REMOTEDIR/old\n\"
		$REXEC rm $REMOTEDIR/old/*\n\"
		$REXEC mv $REMOTEDIR/iperf_c1.txt $REMOTEDIR/old\n\"
		$REXEC exit\n\"
	"
	remote_exec $CLIENT2 "
		$REXEC mkdir -p $REMOTEDIR/old\n\"
		$REXEC rm $REMOTEDIR/old/*\n\"
		$REXEC mv $REMOTEDIR/iperf_c2.txt $REMOTEDIR/old\n\"
		$REXEC exit\n\"
	"
	remote_exec $CLIENT3 "
		$REXEC mkdir -p $REMOTEDIR/old\n\"
		$REXEC rm $REMOTEDIR/old/*\n\"
		$REXEC mv $REMOTEDIR/iperf_c3.txt $REMOTEDIR/old\n\"
		$REXEC exit\n\"
	"
	remote_exec $CLIENT4 "
		$REXEC mkdir -p $REMOTEDIR/old\n\"
		$REXEC rm $REMOTEDIR/old/*\n\"
		$REXEC mv $REMOTEDIR/iperf_c4.txt $REMOTEDIR/old\n\"
		$REXEC exit\n\"
	"

	rm $EVALDIR/results/iperf_c?.txt
	scp $CLIENT1:$REMOTEDIR/old/iperf_c1.txt $EVALDIR/results/
	scp $CLIENT2:$REMOTEDIR/old/iperf_c2.txt $EVALDIR/results/
	scp $CLIENT3:$REMOTEDIR/old/iperf_c3.txt $EVALDIR/results/
	scp $CLIENT4:$REMOTEDIR/old/iperf_c4.txt $EVALDIR/results/
	cp /tmp/bessd.INFO $EVALDIR/results/reconfig_clients.txt
	ssh $CLIENT1 "netstat -nat | grep 5001 > netstat-c1.txt"
	ssh $CLIENT2 "netstat -nat | grep 5002 > netstat-c2.txt"
	ssh $CLIENT3 "netstat -nat | grep 5003 > netstat-c3.txt"
	ssh $CLIENT4 "netstat -nat | grep 5004 > netstat-c4.txt"
	scp $CLIENT1:~/netstat-c1.txt $EVALDIR/results/
	scp $CLIENT2:~/netstat-c2.txt $EVALDIR/results/
	scp $CLIENT3:~/netstat-c3.txt $EVALDIR/results/
	scp $CLIENT4:~/netstat-c4.txt $EVALDIR/results/
}

get_servers_files() {
	remote_exec $SERVER1 "
		$REXEC pkill iperf\n\"
		$REXEC mkdir -p $REMOTEDIR/old\n\"
		$REXEC mv $REMOTEDIR/iperf_s1.txt $REMOTEDIR/old\n\"
		$REXEC exit\n\"
	"
	remote_exec $SERVER2 "
		$REXEC pkill iperf\n\"
		$REXEC mkdir -p $REMOTEDIR/old\n\"
		$REXEC mv $REMOTEDIR/iperf_s2.txt $REMOTEDIR/old\n\"
		$REXEC exit\n\"
	"
	remote_exec $SERVER3 "
		$REXEC pkill iperf\n\"
		$REXEC mkdir -p $REMOTEDIR/old\n\"
		$REXEC mv $REMOTEDIR/iperf_s3.txt $REMOTEDIR/old\n\"
		$REXEC exit\n\"
	"
	remote_exec $SERVER4 "
		$REXEC pkill iperf\n\"
		$REXEC mkdir -p $REMOTEDIR/old\n\"
		$REXEC mv $REMOTEDIR/iperf_s4.txt $REMOTEDIR/old\n\"
		$REXEC exit\n\"
	"

	rm $EVALDIR/results/iperf_s?.txt
	scp $SERVER1:$REMOTEDIR/old/iperf_s1.txt $EVALDIR/results/
	scp $SERVER2:$REMOTEDIR/old/iperf_s2.txt $EVALDIR/results/
	scp $SERVER3:$REMOTEDIR/old/iperf_s3.txt $EVALDIR/results/
	scp $SERVER4:$REMOTEDIR/old/iperf_s4.txt $EVALDIR/results/
	cp /tmp/bessd.INFO $EVALDIR/results/reconfig_servers.txt
}

mkdir -p $EVALDIR/results

if [ $1 == "proxy" ]; then
	if [ $HOSTNAME != $HOST_PROXY ]; then
        	remote_exec $HOST_PROXY "
	                $REXEC cd $EVALDIR\n\"
        	        $REXEC ./get_result.sh proxy\n\"
			$REXEC exit\n\"
        	"
		rm $EVALDIR/results/cpu_proxy_?.txt
		scp $HOST_PROXY:$EVALDIR/results/cpu_proxy_?.txt $EVALDIR/results/
	else
		get_proxy_files
	fi
fi

if [ $1 == "servers" ]; then
	if [ $HOSTNAME != $HOST_SERVERS ]; then
        	remote_exec $HOST_SERVERS "
	                $REXEC cd $EVALDIR\n\"
        	        $REXEC ./get_result.sh servers\n\"
			$REXEC exit\n\"
	        "
		rm $EVALDIR/results/*.txt
	        scp $HOST_SERVERS:$EVALDIR/results/*.txt $EVALDIR/results/
	else
        	get_servers_files
	fi
fi

if [ $1 == "clients" ]; then
	if [ $HOSTNAME != $HOST_CLIENTS ]; then
        	remote_exec $HOST_CLIENTS "
	                $REXEC cd $EVALDIR\n\"
        	        $REXEC ./get_result.sh clients\n\"
			$REXEC exit\n\"
	        "
		rm $EVALDIR/results/*.txt
	        scp $HOST_CLIENTS:$EVALDIR/results/*.txt $EVALDIR/results/
	else
        	get_clients_files
	fi
fi
