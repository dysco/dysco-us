#!/bin/bash

TIMEOUT=1
HOSTNAME=`hostname`
TIME=`date "+%Y%m%d_%H%M%S"`

USER=`whoami`
REXEC="expect -re \"(#|\\\\$) $\"; send \""
REXEC_END="expect -re \"(#|\\\\$) $\""

EVALDIR=/u/ronaldof/udysco/experiments/requests
REMOTEDIR=/root/requests/results

source $EVALDIR/config.sh

remote_exec() {
        expect -c "
                spawn ssh $1
                $2
                expect -re \"(#|\\\\$) $\" ;  send \"exit\r\"
                interact
        "
}

get_client_files() {
	remote_exec $CLIENT5 "
		$REXEC mkdir -p $REMOTEDIR/old\n\"
		$REXEC rm $REMOTEDIR/old/*\n\"
		$REXEC mv $REMOTEDIR/*.txt $REMOTEDIR/old\n\"
		$REXEC exit\n\"
	"
	
	rm $EVALDIR/results/*.txt
	scp $CLIENT5:$REMOTEDIR/old/*.txt $EVALDIR/results/
}

mkdir -p $EVALDIR/results

if [ $HOSTNAME != $HOST_CLIENT ]; then
       	remote_exec $HOST_CLIENT "
	        $REXEC cd $EVALDIR\n\"
        	$REXEC ./get_result.sh\n\"
		$REXEC exit\n\"
        "
	rm $EVALDIR/results/*.txt
	scp $HOST_CLIENT:$EVALDIR/results/*.txt $EVALDIR/results/
else
        get_client_files
fi
