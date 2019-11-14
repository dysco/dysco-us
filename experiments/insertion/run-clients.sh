#!/bin/bash

TIMEOUT=1
HOSTNAME=`hostname`
TIME=`date "+%Y%m%d_%H%M%S"`

USER=`whoami`
REXEC="expect -re \"(#|\\\\$) $\"; send \""
REXEC_END="expect -re \"(#|\\\\$) $\""

EVALDIR=/u/ronaldof/udysco/experiments/insertion
REMOTEDIR=/root/insertion

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
    # $2: SERVER_IP
    # $3: SERVER_PORT
    # $4: DURATION
    # $5: CONN
    # $6: N_CLIENT
    # $7: LHOP
    # $8: RHOP
    # $9: MB_IP
    # $10: TIME_RECONFIG

    remote_exec $1 "
    		$REXEC pkill -9 iperf\n\"
		$REXEC mkdir -p $REMOTEDIR\n\"
		$REXEC $REMOTEDIR/run_client.sh $2 $3 $4 $5 $6 $7 $8 $9 ${10} &\n\"
		"
}

if [ $HOSTNAME != $HOST_CLIENTS ]; then
	remote_exec $HOST_CLIENTS "
		$REXEC cd $EVALDIR\n\"
		$REXEC ./run-clients.sh\n\"
	"
else
    run_client $CLIENT1 $SERVER1_IP $SERVER1_PORT $DURATION $CONN 1 $LHOP $RHOP $FIREWALL_IP $TIME_R1
    run_client $CLIENT2 $SERVER2_IP $SERVER2_PORT $DURATION $CONN 2 $LHOP $RHOP $FIREWALL_IP $TIME_R2
    run_client $CLIENT3 $SERVER3_IP $SERVER3_PORT $DURATION $CONN 3 $LHOP $RHOP $RATE_IP $TIME_R3
fi
