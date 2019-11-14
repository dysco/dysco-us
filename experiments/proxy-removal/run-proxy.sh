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

remote_exec() {
    expect -c "
                spawn ssh $1
                $2
                expect -re \"(#|\\\\$) $\" ;  send \"exit\r\"
                interact
        "
}

run_proxy() {
    # $1: PROXY

    remote_exec $1 "
	    	$REXEC pkill -9 pidstat\n\"
    		$REXEC pkill -9 tcp_proxy\n\"
       		$REXEC mkdir -p $REMOTEDIR\n\"
                $REXEC /root/user/tcp_proxy $PROXY1_IP1 $SERVER1_PORT $SERVER1_IP $SERVER1_PORT $TIME_R1 $LHOP $RHOP &\n\"
                $REXEC pidstat -h -u -p \$\! 1 1> $REMOTEDIR/cpu_proxy_1.txt &\n\"
		$REXEC sleep 1\n\"
                $REXEC /root/user/tcp_proxy $PROXY1_IP1 $SERVER2_PORT $SERVER2_IP $SERVER2_PORT $TIME_R2 $LHOP $RHOP &\n\"
                $REXEC pidstat -h -u -p \$\! 1 1> $REMOTEDIR/cpu_proxy_2.txt &\n\"
		$REXEC sleep 1\n\"
                $REXEC /root/user/tcp_proxy $PROXY1_IP1 $SERVER3_PORT $SERVER3_IP $SERVER3_PORT $TIME_R3 $LHOP $RHOP &\n\"
                $REXEC pidstat -h -u -p \$\! 1 1> $REMOTEDIR/cpu_proxy_3.txt &\n\"
		$REXEC sleep 1\n\"
                $REXEC /root/user/tcp_proxy $PROXY1_IP1 $SERVER4_PORT $SERVER4_IP $SERVER4_PORT $TIME_R4 $LHOP $RHOP &\n\"
                $REXEC pidstat -h -u -p \$\! 1 1> $REMOTEDIR/cpu_proxy_4.txt &\n\"
		$REXEC sleep 1\n\"
        "
}

if [ $HOSTNAME != $HOST_PROXY ]; then
    remote_exec $HOST_PROXY "
		$REXEC cd $EVALDIR\n\"
		$REXEC ./run-proxy.sh &\n\"
	"
else	
    run_proxy $PROXY1 
fi
