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

init_server() {
if [ $SERVER_AND_CLIENT == 1]; then
	if [ $HOSTNAME != $HOST_SERVER ]; then
                remote_exec $HOST_SERVER "
                        $REXEC su\n\"
                        expect \"Password: \"
                        send \"$PW\r\"
                        expect \"\\\\#\"
                        $REXEC /u/ronaldof/udysco/bessctl/bessctl daemon start\r\"
		       	$REXEC DYSCO=$1 SECURE=$2 /u/ronaldof/udysco/bessctl/bessctl run latency-client-and-server\r\"
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
			send \"DYSCO=$1 SECURE=$2 /u/ronaldof/udysco/bessctl/bessctl run latency-client-and-server\r\"
                        expect \"\\\\$\"
			send \"exit\r\"
                "
        fi
else
	if [ $HOSTNAME != $HOST_SERVER ]; then
                remote_exec $HOST_SERVER "
                        $REXEC su\n\"
                        expect \"Password: \"
                        send \"$PW\r\"
                        expect \"\\\\#\"
                        $REXEC /u/ronaldof/udysco/bessctl/bessctl daemon start\r\"
		       	$REXEC DYSCO=$1 SECURE=$2 /u/ronaldof/udysco/bessctl/bessctl run latency-server\r\"
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
			send \"DYSCO=$1 SECURE=$2 /u/ronaldof/udysco/bessctl/bessctl run latency-server\r\"
                        expect \"\\\\$\"
			send \"exit\r\"
                "
        fi
fi
}

init_client() {
if [ $SERVER_AND_CLIENT == 0 ]; then
	if [ $HOSTNAME != $HOST_CLIENT ]; then
                remote_exec $HOST_CLIENT "
                        $REXEC su\n\"
                        expect \"Password: \"
                        send \"$PW\r\"
                        expect \"\\\\#\"
                        $REXEC /u/ronaldof/udysco/bessctl/bessctl daemon start\r\"
		       	$REXEC DYSCO=$1 SECURE=$2 /u/ronaldof/udysco/bessctl/bessctl run latency-client\r\"
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
			send \"DYSCO=$1 SECURE=$2 /u/ronaldof/udysco/bessctl/bessctl run latency-client\r\"
                        expect \"\\\\$\"
                        send \"exit\r\"
		"
	fi
fi
}

init_mbs() {
        if [ $HOSTNAME != $HOST_MBS ]; then
                remote_exec $HOST_MBS "
                        $REXEC su\n\"
                        expect \"Password: \"
                        send \"$PW\r\"
                        expect \"\\\\#\"
                        $REXEC /u/ronaldof/udysco/bessctl/bessctl daemon start\r\"
		       	$REXEC DYSCO=$1 SECURE=$2 /u/ronaldof/udysco/bessctl/bessctl run latency-mbs\r\"
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
			send \"DYSCO=$1 SECURE=$2 /u/ronaldof/udysco/bessctl/bessctl run latency-mbs\r\"
                        expect \"\\\\$\"
                        send \"exit\r\"
                "
        fi

}

get_cabernet_password

clear

echo $(TZ=America/New_York date)
echo -n "[$(TZ=America/New_York date +"%T.%6N")] Starting virtual machines without Dysco... "
{
        init_mbs    $WO_DYSCO $NO_SECURE
        init_server $WO_DYSCO $NO_SECURE
	init_client $WO_DYSCO $NO_SECURE
} &> /dev/null
sleep 35
echo "Done."
echo "[$(TZ=America/New_York date +"%T.%6N")] Running the experiment... "
echo -ne "\t[$(TZ=America/New_York date +"%T.%6N")] 1st experiment... " 
$EVALDIR/run-mbs.sh $WO_DYSCO 0 &>/dev/null
$EVALDIR/run-server.sh $WO_DYSCO 0 &>/dev/null
$EVALDIR/run-client.sh $WO_DYSCO 0 &>/dev/null
echo "Done."
echo -ne "\t[$(TZ=America/New_York date +"%T.%6N")] 2nd experiment... " 
$EVALDIR/run-mbs.sh $WO_DYSCO 1 &>/dev/null
$EVALDIR/run-server.sh $WO_DYSCO 1 &>/dev/null
$EVALDIR/run-client.sh $WO_DYSCO 1 &>/dev/null
echo "Done."
echo -ne "\t[$(TZ=America/New_York date +"%T.%6N")] 3rd experiment... " 
$EVALDIR/run-mbs.sh $WO_DYSCO 2 &>/dev/null
$EVALDIR/run-server.sh $WO_DYSCO 2 &>/dev/null
$EVALDIR/run-client.sh $WO_DYSCO 2 &>/dev/null
echo "Done."
echo -ne "\t[$(TZ=America/New_York date +"%T.%6N")] 4th experiment... " 
$EVALDIR/run-mbs.sh $WO_DYSCO 3 &>/dev/null
$EVALDIR/run-server.sh $WO_DYSCO 3 &>/dev/null
$EVALDIR/run-client.sh $WO_DYSCO 3 &>/dev/null
echo "Done."
echo -ne "\t[$(TZ=America/New_York date +"%T.%6N")] 5th experiment... " 
$EVALDIR/run-mbs.sh $WO_DYSCO 4 &>/dev/null
$EVALDIR/run-server.sh $WO_DYSCO 4 &>/dev/null
$EVALDIR/run-client.sh $WO_DYSCO 4 &>/dev/null
echo "Done."

echo -n "[$(TZ=America/New_York date +"%T.%6N")] Starting virtual machines with regular Dysco... "
{
        init_mbs    $W_DYSCO $NO_SECURE
        init_server $W_DYSCO $NO_SECURE
	init_client $W_DYSCO $NO_SECURE
} &> /dev/null
sleep 35
echo "Done."
echo "[$(TZ=America/New_York date +"%T.%6N")] Running the experiment... "
echo -ne "\t[$(TZ=America/New_York date +"%T.%6N")] 1st experiment... " 
$EVALDIR/run-mbs.sh $W_DYSCO 0 &>/dev/null
$EVALDIR/run-server.sh $W_DYSCO 0 &>/dev/null
$EVALDIR/run-client.sh $W_DYSCO 0 &>/dev/null
echo "Done."
echo -ne "\t[$(TZ=America/New_York date +"%T.%6N")] 2nd experiment... " 
$EVALDIR/run-mbs.sh $W_DYSCO 1 &>/dev/null
$EVALDIR/run-server.sh $W_DYSCO 1 &>/dev/null
$EVALDIR/run-client.sh $W_DYSCO 1 &>/dev/null
echo "Done."
echo -ne "\t[$(TZ=America/New_York date +"%T.%6N")] 3rd experiment... " 
$EVALDIR/run-mbs.sh $W_DYSCO 2 &>/dev/null
$EVALDIR/run-server.sh $W_DYSCO 2 &>/dev/null
$EVALDIR/run-client.sh $W_DYSCO 2 &>/dev/null
echo "Done."
echo -ne "\t[$(TZ=America/New_York date +"%T.%6N")] 4th experiment... " 
$EVALDIR/run-mbs.sh $W_DYSCO 3 &>/dev/null
$EVALDIR/run-server.sh $W_DYSCO 3 &>/dev/null
$EVALDIR/run-client.sh $W_DYSCO 3 &>/dev/null
echo "Done."
echo -ne "\t[$(TZ=America/New_York date +"%T.%6N")] 5th experiment... " 
$EVALDIR/run-mbs.sh $W_DYSCO 4 &>/dev/null
$EVALDIR/run-server.sh $W_DYSCO 4 &>/dev/null
$EVALDIR/run-client.sh $W_DYSCO 4 &>/dev/null
echo "Done."

echo -n "[$(TZ=America/New_York date +"%T.%6N")] Starting virtual machines with Secure Dysco... "
{
        init_mbs    $W_DYSCO $SECURE
        init_server $W_DYSCO $SECURE
	init_client $W_DYSCO $SECURE
} &> /dev/null
sleep 35
echo "Done."
echo "[$(TZ=America/New_York date +"%T.%6N")] Running the experiment... "
echo -ne "\t[$(TZ=America/New_York date +"%T.%6N")] 1st experiment... "
$EVALDIR/run-mbs.sh $SECURE_DYSCO 0 &>/dev/null
$EVALDIR/run-server.sh $SECURE_DYSCO 0 &>/dev/null
$EVALDIR/run-client.sh $SECURE_DYSCO 0 &>/dev/null
echo "Done."
echo -ne "\t[$(TZ=America/New_York date +"%T.%6N")] 2nd experiment... "
$EVALDIR/run-mbs.sh $SECURE_DYSCO 1 &>/dev/null
$EVALDIR/run-server.sh $SECURE_DYSCO 1 &>/dev/null
$EVALDIR/run-client.sh $SECURE_DYSCO 1 &>/dev/null
echo "Done."
echo -ne "\t[$(TZ=America/New_York date +"%T.%6N")] 3rd experiment... "
$EVALDIR/run-mbs.sh $SECURE_DYSCO 2 &>/dev/null
$EVALDIR/run-server.sh $SECURE_DYSCO 2 &>/dev/null
$EVALDIR/run-client.sh $SECURE_DYSCO 2 &>/dev/null
echo "Done."
echo -ne "\t[$(TZ=America/New_York date +"%T.%6N")] 4th experiment... "
$EVALDIR/run-mbs.sh $SECURE_DYSCO 3 &>/dev/null
$EVALDIR/run-server.sh $SECURE_DYSCO 3 &>/dev/null
$EVALDIR/run-client.sh $SECURE_DYSCO 3 &>/dev/null
echo "Done."
echo -ne "\t[$(TZ=America/New_York date +"%T.%6N")] 5th experiment... "
$EVALDIR/run-mbs.sh $SECURE_DYSCO 4 &>/dev/null
$EVALDIR/run-server.sh $SECURE_DYSCO 4 &>/dev/null
$EVALDIR/run-client.sh $SECURE_DYSCO 4 &>/dev/null
echo "Done."

echo -n "[$(TZ=America/New_York date +"%T.%6N")] Collecting the results... "
{
    $EVALDIR/get_result.sh
} &> /dev/null
echo "Done."

echo $(TZ=America/New_York date)
