#!/bin/bash

TIMEOUT=1
HOSTNAME=`hostname`
TIME=`date "+%Y%m%d_%H%M%S"`

USER=`whoami`
REXEC="expect -re \"(#|\\\\$) $\"; send \""
REXEC_END="expect -re \"(#|\\\\$) $\""

EVALDIR=/u/ronaldof/udysco/experiments/nat-crossing
REMOTEDIR=/root/nat/results

source $EVALDIR/config.sh

remote_exec() {
    expect -c "
                spawn ssh $1
                $2
                expect -re \"(#|\\\\$) $\" ;  send \"exit\r\"
                interact
        "
}

run_client_1() {
    # $1: CLIENT
    # $2: IP_ADDRESS
    # $3: PORT
    # $4: DURATION
    # $5: CONN
    # $6: DIRECTION
    # $7: LHOP
    # $8: RHOP
    # $9: TIME_RECONFIG
    # $10: MB1
    # $11: MB2

    remote_exec $1 "
		$REXEC pkill -9 iperf\n\"
		$REXEC mkdir -p $REMOTEDIR\n\"
                $REXEC /root/run_client.sh $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 &\n\"
	"
}

run_client_2() {
    # $1: CLIENT
    # $2: IP_ADDRESS
    # $3: PORT
    # $4: DURATION
    # $5: CONN
    # $6: DIRECTION
    # $7: LHOP
    # $8: RHOP
    # $9: TIME_RECONFIG

    remote_exec $1 "
		$REXEC pkill -9 iperf\n\"
		$REXEC mkdir -p $REMOTEDIR\n\"
                $REXEC /root/run_client.sh $2 $3 $4 $5 $6 $7 $8 $9 &\n\"
	"
}

if [ $HOSTNAME != $HOST_CLIENTS ]; then
    remote_exec $HOST_CLIENTS "
		$REXEC cd $EVALDIR\n\"
		$REXEC ./run-clients.sh &\n\"
	"
else
    run_client_1 $CLIENT1 $SERVER1 $SERVER1_PORT1 $DURATION $CONN $DIRECTION 0 1 $TIME_RECONFIG $MB1 $MB2
    sleep $(($DURATION+5))
    run_client_2 $CLIENT1 $SERVER1 $SERVER1_PORT2 $DURATION $CONN $DIRECTION 0 3 $TIME_RECONFIG
    sleep $(($DURATION+5))
fi
