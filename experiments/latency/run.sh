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
    		set timeout $TIMEOUT
           	spawn ssh $1
           	$2
           	expect -re \"(#|\\\\$) $\" ;  send \"exit\r\"
           	interact
	"
}

run_mb() {
	#$1: Middlebox name
	#$2: Command to run on middlebox
    
	if [ $HOSTNAME == $HOST_MBS ]; then
		ssh $1 "$2"
    	else
		remote_exec $HOST_MBS "
        	 	$REXEC ssh $1 \'$2\'\n\"
		"
    	fi
}

run_client() {
	#$1: Command to run on client

	if [ $HOSTNAME == $HOST_CLIENT ]; then
		ssh client4 "$1"
    	else
		remote_exec $HOST_CLIENT "
			$REXEC ssh client4 \'$1\'\n\"
		"
    	fi
}

run_server() {
	#$1: Command to run on server

    	if [ $HOSTNAME == $HOST_SERVER ]; then
		ssh server4 "$1"
    	else
		remote_exec $HOST_SERVER "
			$REXEC ssh server4 \'$1\'\n\"
		"
    	fi
}

if [ $MBS == 0 ]; then
    	run_server "source ~/latency/0.sh"
    	run_client "source ~/latency/0.sh"
elif [ $MBS == 1 ]; then
    	run_server   "source ~/latency/default.sh"
    	run_mb "mb3" "source ~/latency/1.sh"
    	run_client   "source ~/latency/1.sh"
elif [ $MBS == 2 ]; then
    	run_server   "source ~/latency/default.sh"
    	run_mb "mb3" "source ~/latency/default.sh"
    	run_mb "mb2" "source ~/latency/2.sh"
    	run_client   "source ~/latency/2.sh"
elif [ $MBS == 3 ]; then
    	run_server   "source ~/latency/default.sh"
    	run_mb "mb3" "source ~/latency/default.sh"
    	run_mb "mb2" "source ~/latency/default.sh"
    	run_mb "mb1" "source ~/latency/3.sh"
    	run_client   "source ~/latency/3.sh"
elif [ $MBS == 4 ]; then
    	run_server   "source ~/latency/default.sh"
    	run_mb "mb3" "source ~/latency/default.sh"
    	run_mb "mb2" "source ~/latency/default.sh"
    	run_mb "mb1" "source ~/latency/default.sh"
    	run_mb "mb0" "source ~/latency/4.sh"
    	run_client   "source ~/latency/4.sh"
else
    	exit 1
fi

sleep 5

run_server "pkill -9 latency-server"
run_server "/etc/init.d/nginx stop"
run_server "/root/latency/latency-server 9900 &"
run_server "/root/latency/latency-server 9901 &"
run_server "/root/latency/latency-server 9902 &"
run_server "/root/latency/latency-server 9903 &"
run_server "/root/latency/latency-server 9904 &"

sleep 10

run_client "mkdir -p $REMOTEDIR"
run_client "/root/latency/latency-client $SERVER5_IP 990$MBS > $REMOTEDIR/$MBS-$DYSCO.txt"
