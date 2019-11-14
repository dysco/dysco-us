#!/bin/bash

TIMEOUT=1
HOSTNAME=`hostname`
TIME=`date "+%Y%m%d_%H%M%S"`

USER=`whoami`
REXEC="expect -re \"(#|\\\\$) $\"; send \""
REXEC_END="expect -re \"(#|\\\\$) $\""

EVALDIR=/u/ronaldof/udysco/experiments/nat-crossing
REMOTEDIR=/root/nat/results

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

init_servers() {
    if [ $HOSTNAME != $HOST_SERVERS ]; then
	remote_exec $HOST_SERVERS "
                        $REXEC su\n\"
                        expect \"Password: \"
                        send \"$PW\r\"
                        expect \"\\\\#\"
                        $REXEC /u/ronaldof/udysco/bessctl/bessctl daemon start\r\" 
                        $REXEC DYSCO=$1 /u/ronaldof/udysco/bessctl/bessctl run nat-servers\r\"
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
                        send \"DYSCO=$1 /u/ronaldof/udysco/bessctl/bessctl run nat-servers\r\"
                        expect \"\\\\$\"
                        send \"exit\r\"
                "
    fi
}

init_clients() {
    if [ $HOSTNAME != $HOST_CLIENTS ]; then
        remote_exec $HOST_CLIENTS "
                        $REXEC su\n\"
                        expect \"Password: \"
                        send \"$PW\r\"
                        expect \"\\\\#\"
                        $REXEC /u/ronaldof/udysco/bessctl/bessctl daemon start\r\" 
                        $REXEC DYSCO=$1 /u/ronaldof/udysco/bessctl/bessctl run nat-clients\r\"
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
                        send \"DYSCO=$1 /u/ronaldof/udysco/bessctl/bessctl run nat-clients\r\"
                        expect \"\\\\$\"
                        send \"exit\r\"
                "
    fi 
}

get_cabernet_password

clear
echo $(TZ=America/New_York date)
echo -n "[$(TZ=America/New_York date +"%T.%6N")] Starting virtual machines... "
{
        init_servers $DYSCO
	init_clients $DYSCO
} &> /dev/null
sleep 35
echo "Done."
echo -n "[$(TZ=America/Campo_Grande date +"%T.%6N")] Running the experiment... "
{
        $EVALDIR/run-clients.sh
} &> /dev/null
echo "Done."
sleep 5
sleep $DURATION
sleep 5
sleep $DURATION
sleep 10
echo -n "[$(TZ=America/Campo_Grande date +"%T.%6N")] Collecting the results... "
{
    $EVALDIR/get_result.sh servers
} &> /dev/null
echo "Done."

echo $(TZ=America/New_York date)
