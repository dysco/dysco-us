#!/bin/bash

TIMEOUT=1
HOSTNAME=`hostname`
TIME=`date "+%Y%m%d_%H%M%S"`

USER=`whoami`
REXEC="expect -re \"(#|\\\\$) $\"; send \""
REXEC_END="expect -re \"(#|\\\\$) $\""

EVALDIR=/u/ronaldof/udysco/experiments/performance
REMOTEDIR=/root/performance/results

source $EVALDIR/config.sh

if [ $# -ne 1 ]; then
	echo "$0 <sender|receiver>"
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

mkdir -p $EVALDIR/results

if [ $1 == "sender" ]; then
	if [ $HOSTNAME != $HOST_SENDER ]; then
	        scp $HOST_SENDER:$EVALDIR/results/* $EVALDIR/results/
	fi
fi

if [ $1 == "receiver" ]; then
	if [ $HOSTNAME != $HOST_RECEIVER ]; then
	        scp $HOST_RECEIVER:$EVALDIR/results/* $EVALDIR/results/
	fi
fi
