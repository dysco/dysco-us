#!/bin/bash

TIMEOUT=1
HOSTNAME=`hostname`
TIME=`date "+%Y%m%d_%H%M%S"`

USER=`whoami`
REXEC="expect -re \"(#|\\\\$) $\"; send \""
REXEC_END="expect -re \"(#|\\\\$) $\""

EVALDIR=/u/ronaldof/udysco/experiments/latency
REMOTEDIR=/root/latency/results

source $EVALDIR/config.sh

if [ $# -ne 2 ]; then
	echo "$0 <Dysco=[0|1|2]> <# mbs>"
	exit 1
fi 

MBS=$2
DYSCO=$1

remote_exec() {
	expect -c "
           	spawn ssh $1
           	$2
           	expect -re \"(#|\\\\$) $\" ;  send \"exit\r\"
           	interact
	"
}

run_server() {
	#$1: Command to run on server

	{
		remote_exec $SERVER5 "
			$REXEC $1\r\"
		"
	} &> /dev/null
}

if [ $HOSTNAME != $HOST_SERVER ]; then
	remote_exec $HOST_SERVER "
		$REXEC cd $EVALDIR\n\"
		$REXEC ./run-server.sh $DYSCO $MBS \r\"
		expect \"OK\"
	"
	sleep 1
else
	if [ $MBS == 0 ]; then
    		run_server "source ~/latency/0.sh"
	else
    		run_server "source ~/latency/default.sh"
	fi
fi

run_server "pkill -9 latency-server"
run_server "/etc/init.d/nginx stop"
run_server "/root/latency/latency-server 9900 &"
run_server "/root/latency/latency-server 9901 &"
run_server "/root/latency/latency-server 9902 &"
run_server "/root/latency/latency-server 9903 &"
run_server "/root/latency/latency-server 9904 &"

echo "OK"
