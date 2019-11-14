#!/bin/bash

TIMEOUT=1
HOSTNAME=`hostname`
TIME=`date "+%Y%m%d_%H%M%S"`

USER=`whoami`
REXEC="expect -re \"(#|\\\\$) $\"; send \""
REXEC_END="expect -re \"(#|\\\\$) $\""

EVALDIR=/u/ronaldof/udysco/experiments/fwd-removal
REMOTEDIR=/root/fwd-removal

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
    # $9: TIME_RECONFIG

    remote_exec $1 "
    		$REXEC pkill -9 iperf\n\"
		$REXEC mkdir -p $REMOTEDIR\n\"
		$REXEC $REMOTEDIR/run_client.sh $2 $3 $4 $5 $6 $7 $8 $9 &\n\"
		"
}

if [ $HOSTNAME != $HOST_CLIENT ]; then
	remote_exec $HOST_CLIENT "
		$REXEC cd $EVALDIR\n\"
		$REXEC ./run-client.sh\n\"
	"
else
    run_client $CLIENT $SERVER_IP $SERVER_PORT $DURATION $CONN 1 $LHOP $RHOP $TIME_R1
fi
