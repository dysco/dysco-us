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

run_client() {
	#$1: Command to run on client

	{
		remote_exec $CLIENT5 "
			$REXEC $1\r\"
		"
	} &> /dev/null
}

if [ $HOSTNAME != $HOST_CLIENT ]; then
	remote_exec $HOST_CLIENT "
		$REXEC cd $EVALDIR\n\"
		$REXEC ./run-client.sh $DYSCO $MBS\r\"
		expect \"OK\"
	"
	sleep 1
else
	if [ $MBS == 0 ]; then
    		run_client "source ~/latency/0.sh"
	elif [ $MBS == 1 ]; then
    		run_client   "source ~/latency/1.sh"
	elif [ $MBS == 2 ]; then
    		run_client   "source ~/latency/2.sh"
	elif [ $MBS == 3 ]; then
    		run_client   "source ~/latency/3.sh"
	elif [ $MBS == 4 ]; then
    		run_client   "source ~/latency/4.sh"
	fi
fi

sleep 5

run_client "mkdir -p $REMOTEDIR"
for i in `seq 1 $N_SAMPLES`; do
	run_client "/root/requests/wrk/wrk -d $DURATION -c $CONN -t $THREADS http://$SERVER5_IP:808$MBS > $REMOTEDIR/$MBS-$DYSCO-n$i.txt"
	sleep 1
done

echo "OK"
