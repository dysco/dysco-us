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

run_client() {
    # $1: CLIENT
    # $2: IP_ADDRESS
    # $3: PORT
    # $4: DURATION
    # $5: CONN
    # $6: N_CLIENT

    remote_exec $1 "
		$REXEC pkill -9 iperf\n\"
		$REXEC mkdir -p $REMOTEDIR\n\"
                $REXEC /root/iperf -c $2 -p $3 -t $4 -P $5 -i 1 -f m > $REMOTEDIR/iperf_c$6.txt & \n\"
	"
}

if [ $HOSTNAME != $HOST_CLIENTS ]; then
    remote_exec $HOST_CLIENTS "
		$REXEC cd $EVALDIR\n\"
		$REXEC ./run-clients.sh &\n\"
	"
else
    run_client $CLIENT1 $PROXY1_IP1 $SERVER1_PORT $DURATION $CONN 1 
    run_client $CLIENT2 $PROXY1_IP1 $SERVER2_PORT $DURATION $CONN 2 
    run_client $CLIENT3 $PROXY1_IP1 $SERVER3_PORT $DURATION $CONN 3 
    run_client $CLIENT4 $PROXY1_IP1 $SERVER4_PORT $DURATION $CONN 4
fi
