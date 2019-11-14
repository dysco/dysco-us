#!/bin/bash

TIMEOUT=3
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

run_mb() {
	#$1: Middlebox name
	#$2: Command to run on middlebox
  
        {	
		remote_exec $1 "
        		$REXEC $2\r\"
		"
	} &> /dev/null
}

if [ $HOSTNAME != $HOST_MBS ]; then
	remote_exec $HOST_MBS "
		$REXEC cd $EVALDIR\n\"
		$REXEC ./run-mbs.sh $DYSCO $MBS \r\"
		expect \"OK\"
	"
	sleep 1
else
	if [ $MBS == 1 ]; then
    		run_mb "mb3" "source ~/latency/1.sh"
	elif [ $MBS == 2 ]; then
    		run_mb "mb3" "source ~/latency/default.sh"
	    	run_mb "mb2" "source ~/latency/2.sh"
	elif [ $MBS == 3 ]; then
	    	run_mb "mb3" "source ~/latency/default.sh"
    		run_mb "mb2" "source ~/latency/default.sh"
	    	run_mb "mb1" "source ~/latency/3.sh"
	elif [ $MBS == 4 ]; then
    		run_mb "mb3" "source ~/latency/default.sh"
	    	run_mb "mb2" "source ~/latency/default.sh"
	    	run_mb "mb1" "source ~/latency/default.sh"
	    	run_mb "mb0" "source ~/latency/4.sh"
	fi
	echo "OK"
fi
