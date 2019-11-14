#!/bin/bash

TIMEOUT=1
HOSTNAME=`hostname`
TIME=`date "+%Y%m%d_%H%M%S"`

USER=`whoami`
REXEC="expect -re \"(#|\\\\$) $\"; send \""
REXEC_END="expect -re \"(#|\\\\$) $\""

EVALDIR=/u/ronaldof/udysco/experiments/reconfig
REMOTEDIR=/root/reconfig

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

get_server_files() {
	remote_exec $SERVER "
		$REXEC pkill iperf\n\"
		$REXEC mkdir -p $REMOTEDIR/old\n\"
		$REXEC mv $REMOTEDIR/iperf_s1.txt $REMOTEDIR/old\n\"
		$REXEC exit\n\"
	"
	
	rm $EVALDIR/results/iperf_s?.txt
	scp $SERVER1:$REMOTEDIR/old/iperf_s1.txt $EVALDIR/results/
}

mkdir -p $EVALDIR/results

if [ $1 == "servers" ]; then
	if [ $HOSTNAME != $HOST_SERVER ]; then
        	remote_exec $HOST_SERVER "
	                $REXEC cd $EVALDIR\n\"
        	        $REXEC ./get_results.sh servers\n\"
			$REXEC exit\n\"
	        "
		rm $EVALDIR/results/iperf_s?.txt
	        scp $HOST_SERVER:$EVALDIR/results/iperf_s?.txt $EVALDIR/results/
	else
        	get_server_files
	fi
fi
