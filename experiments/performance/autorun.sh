#!/bin/bash

TIMEOUT=1
HOSTNAME=`hostname`
TIME=`date "+%Y%m%d_%H%M%S"`

USER=`whoami`
REXEC="expect -re \"(#|\\\\$) $\"; send \""
REXEC_END="expect -re \"(#|\\\\$) $\""

EVALDIR=/u/ronaldof/udysco/experiments/performance
REMOTEDIR=$EVALDIR/results

source $EVALDIR/config.sh

remote_exec() {
    expect -c "
           spawn ssh $1
           $2
           expect -re \"(#|\\\\$) $\" ;  send \"exit\r\"
           interact
           "
}

get_cabernet_password() {
        echo -n "Cabernet password: "
        stty -echo
        read PW
        stty echo
        echo
}

init_sender() {
	# $1: W_DYSCO or WO_DYSCO (1digit)
	# $2: PKT_SIZE (4digits)
	# $3: CORES (2digits)
	# $4: RANGE

	if [ $HOSTNAME != $HOST_SENDER ]; then
		remote_exec $HOST_SENDER "
			$REXEC su\n\"
                        expect \"Password: \"
                        send \"$PW\r\"
                        expect \"\\\\#\"
                        $REXEC /u/ronaldof/udysco/bessctl/bessctl daemon start\r\"
		       	$REXEC DYSCO=$1 BESS_CORES=$3 TCP_SIZE=$2 TCP_RANGE=$4 /u/ronaldof/udysco/bessctl/bessctl run performance-sender\r\"
                        $REXEC exit\r\"
		"
	else
		expect -c "
                        spawn su
                        expect \"Password: \"
                        send \"$PW\r\"
                        expect \"\\\\$\"
			send \"/u/ronaldof/udysco/bessctl/bessctl daemon start\r\"
		       	expect \"\\\\$\"
			send \"DYSCO=$1 BESS_CORES=$3 TCP_SIZE=$2 TCP_RANGE=$4 /u/ronaldof/udysco/bessctl/bessctl run performance-sender\r\"
			expect \"\\\\$\"
                        send \"exit\r\"
                        expect \"\\\\$\"
		"
	fi
}

init_receiver() {
        # $1: W_DYSCO or WO_DYSCO (1digit)
        # $2: PKT_SIZE (4digits)
        # $3: CORES (2digits)

        if [ $HOSTNAME != $HOST_RECEIVER ]; then
                remote_exec $HOST_RECEIVER "
                        $REXEC su\n\"
                        expect \"Password: \"
                        send \"$PW\r\"
                        expect \"\\\\#\"
                        $REXEC /u/ronaldof/udysco/bessctl/bessctl daemon start\r\"
			$REXEC DYSCO=$1 BESS_CORES=$3 /u/ronaldof/udysco/bessctl/bessctl run performance-receiver\r\"
                        $REXEC exit\r\"
                "
        else
                expect -c "
                        spawn su
                        expect \"Password: \"
                        send \"$PW\r\"
                        expect \"\\\\$\"
                        send \"/u/ronaldof/udysco/bessctl/bessctl daemon start\r\"
		       	expect \"\\\\$\"
			send \"DYSCO=$1 BESS_CORES=$3 /u/ronaldof/udysco/bessctl/bessctl run performance-receiver\r\"
                        expect \"\\\\$\"
                        send \"exit\r\"
                        expect \"\\\\$\"
                "
        fi
}

start_sender() {
        # $1: W_DYSCO or WO_DYSCO (1digit)
        # $2: PKT_SIZE (4digits)
        # $3: CORES (2digits)

	if [ $HOSTNAME != $HOST_SENDER ]; then
		remote_exec $HOST_SENDER "
			$REXEC export CSV=$REMOTEDIR/$2-tx-$1-$3\r\"
                        $REXEC nohup /u/ronaldof/udysco/bessctl/bessctl monitor port > 
/dev/null 2>&1 &\r\"
                        $REXEC exit\r\"
                "
	else
		expect -c "
			spawn bash
			expect \"\\\\$\"
			send \"export CSV=$REMOTEDIR/$2-tx-$1-$3\r\"
			expect \"\\\\$\"
			send \"nohup /u/ronaldof/udysco/bessctl/bessctl monitor port > /dev/null 2>&1 &\r\"
			expect \"\\\\$\"
			send \"exit\r\"
			expect \"\\\\$\"
		"
	fi
}

start_receiver() {
        # $1: W_DYSCO or WO_DYSCO (1digit)
        # $2: PKT_SIZE (4digits)
        # $3: CORES (2digits)

	if [ $HOSTNAME != $HOST_RECEIVER ]; then
		remote_exec $HOST_RECEIVER "
			$REXEC export CSV=$REMOTEDIR/$2-rx-$1-$3\r\"
                        $REXEC nohup /u/ronaldof/udysco/bessctl/bessctl monitor port > /dev/null 2>&1 &\r\"
                        $REXEC exit\r\"
                "
	else
		expect -c "
			spawn bash
                        expect \"\\\\$\"
                        send \"export CSV=$REMOTEDIR/$2-tx-$1-$3\r\"
                        expect \"\\\\$\"
                        send \"nohup /u/ronaldof/udysco/bessctl/bessctl monitor port > /dev/null 2>&1 &\r\"
                        expect \"\\\\$\"
                        send \"exit\r\"
                        expect \"\\\\$\"	
                "
	fi
}

stop_sender() {
	if [ $HOSTNAME != $HOST_SENDER ]; then
                remote_exec $HOST_SENDER "
                        $REXEC ps -axf | grep monitor | grep port | awk \'{print \\\$1}\' | xargs kill -s SIGINT\r\"
                        $REXEC exit\r\"
                "
        else
                expect -c "
                        spawn bash
                        expect \"\\\\$\"
                        send \"ps -axf | grep monitor | grep port | awk '{print \\\$1}'| xargs kill -s SIGINT\r\"
                        expect \"\\\\$\"
                        send \"exit\r\"
                        expect \"\\\\$\"
                "
        fi
}

stop_receiver() {
        if [ $HOSTNAME != $HOST_RECEIVER ]; then
                remote_exec $HOST_RECEIVER "
                        $REXEC ps -axf | grep monitor | grep port | awk \'{print \\\$1}\' | xargs kill -s SIGINT\r\"
                        $REXEC exit\r\"
                "
        else
                expect -c "
			spawn bash
                        expect \"\\\\$\"
                        send \"ps -axf | grep monitor | grep port | awk '{print \\\$1}'| xargs kill -s SIGINT\r\"
                        expect \"\\\\$\"
                        send \"exit\r\"
                        expect \"\\\\$\"
                "
        fi
}
		
get_cabernet_password

clear
echo $(TZ=America/New_York date)
echo "[$(TZ=America/New_York date +"%T.%6N")] Running the 1st experiment with $CORES logical core(s)"
for i in 0064 0128 0256 0512 1024 1280 1518; do
	echo -ne "\t[$(TZ=America/New_York date +"%T.%6N")] Packets with $(echo $i|sed 's/^0*//g') bytes... "
	{
		init_receiver $WO_DYSCO $i $CORES
		init_sender   $WO_DYSCO $i $CORES $TCP_RANGE
		sleep $ESTABLISH_TIME
		start_receiver $WO_DYSCO $i $CORES
		start_sender   $WO_DYSCO $i $CORES
		sleep $EXPERIMENT_TIME
		stop_receiver
		stop_sender
	} &> /dev/null
        {
                init_receiver $W_DYSCO $i $CORES
                init_sender   $W_DYSCO $i $CORES $TCP_RANGE
                sleep $ESTABLISH_TIME
                start_receiver $W_DYSCO $i $CORES
                start_sender   $W_DYSCO $i $CORES
                sleep $EXPERIMENT_TIME
                stop_receiver
                stop_sender
        } &> /dev/null
	echo "Done."
done

echo -n "[$(TZ=America/New_York date +"%T.%6N")] Collecting the results... "
{
	$EVALDIR/get_result.sh sender
	$EVALDIR/get_result.sh receiver
} &> /dev/null
echo "Done."

echo $(TZ=America/New_York date)
