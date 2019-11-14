#!/bin/bash

TIMEOUT=1
HOSTNAME=`hostname`
TIME=`date "+%Y%m%d_%H%M%S"`

USER=`whoami`
REXEC="expect -re \"(#|\\\\$) $\"; send \""
REXEC_END="expect -re \"(#|\\\\$) $\""

EVALDIR=/u/ronaldof/udysco/experiments/nat-crossing
REMOTEDIR=/root/removal/results

source $EVALDIR/config.sh

remote_exec() {
        expect -c "
                set timeout $TIMEOUT
                spawn ssh $1
                $2
                expect -re \"(#|\\\\$) $\" ;  send \"exit\r\"
                interact
        "
}

run_server() {
        # $1: SERVER
        # $2: PORT
        # $3: N_SERVER

	remote_exec $1 "
		$REXEC pkill -9 iperf\n\"
		$REXEC mkdir -p $REMOTEDIR\n\"
		$REXEC /root/iperf -s -q 200 -p$2 -i1 -f g > $REMOTEDIR/iperf_s$3.txt &\n\"
	"
}

if [ $HOSTNAME != $HOST_SERVERS ]; then
	remote_exec $HOST_SERVERS "
		$REXEC cd $EVALDIR\n\"
		$REXEC ./run-servers.sh &\n\"
	"
else	
	run_server $SERVER1 $SERVER1_PORT 1
	run_server $SERVER2 $SERVER2_PORT 2
	run_server $SERVER3 $SERVER3_PORT 3
	run_server $SERVER4 $SERVER4_PORT 4
fi
