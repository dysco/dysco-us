#!/bin/bash

TIMEOUT=1
HOSTNAME=`hostname`
TIME=`date "+%Y%m%d_%H%M%S"`

USER=`whoami`
REXEC="expect -re \"(#|\\\\$) $\"; send \""
REXEC_END="expect -re \"(#|\\\\$) $\""

EVALDIR=/u/ronaldof/udysco/experiments/proxy-removal
REMOTEDIR=/root/removal/results

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

init_proxy() {
        if [ $HOSTNAME != $HOST_PROXY ]; then
                remote_exec $HOST_PROXY "
                        $REXEC su\n\"
                        expect \"Password: \"
                        send \"$PW\r\"
                        expect \"\\\\#\"
                        $REXEC /u/ronaldof/udysco/bessctl/bessctl daemon start\r\"
			$REXEC DYSCO=$1 /u/ronaldof/udysco/bessctl/bessctl run removal-proxy\r\"
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
			send \"DYSCO=$1 /u/ronaldof/udysco/bessctl/bessctl run removal-proxy\r\"
                        expect \"\\\\$\"
                        send \"exit\r\"
                "
        fi
}

init_servers() {
    if [ $SERVERS_AND_CLIENTS == 1 ]; then
	if [ $HOSTNAME != $HOST_SERVERS ]; then
            remote_exec $HOST_SERVERS "
                        $REXEC su\n\"
                        expect \"Password: \"
                        send \"$PW\r\"
                        expect \"\\\\#\"
                        $REXEC /u/ronaldof/udysco/bessctl/bessctl daemon start\r\" 
			$REXEC DYSCO=$1 /u/ronaldof/udysco/bessctl/bessctl run removal-clients-and-servers\r\"
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
			send \"DYSCO=$1 /u/ronaldof/udysco/bessctl/bessctl run removal-clients-and-servers\r\"
                        expect \"\\\\$\"
                        send \"exit\r\"
                "
        fi
    else
	if [ $SINGLE_CORE == 1 ]; then
	    if [ $HOSTNAME != $HOST_SERVERS ]; then
		remote_exec $HOST_SERVERS "
                        $REXEC su\n\"
                        expect \"Password: \"
                        send \"$PW\r\"
                        expect \"\\\\#\"
                        $REXEC /u/ronaldof/udysco/bessctl/bessctl daemon start\r\" 
                        $REXEC DYSCO=$1 /u/ronaldof/udysco/bessctl/bessctl run removal-servers-1core\r\"
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
                        send \"DYSCO=$1 /u/ronaldof/udysco/bessctl/bessctl run removal-servers-1core\r\"
                        expect \"\\\\$\"
                        send \"exit\r\"
                "
            fi
	else
	    if [ $HOSTNAME != $HOST_SERVERS ]; then
		remote_exec $HOST_SERVERS "
                        $REXEC su\n\"
                        expect \"Password: \"
                        send \"$PW\r\"
                        expect \"\\\\#\"
                        $REXEC /u/ronaldof/udysco/bessctl/bessctl daemon start\r\" 
                        $REXEC DYSCO=$1 /u/ronaldof/udysco/bessctl/bessctl run removal-servers\r\"
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
                        send \"DYSCO=$1 /u/ronaldof/udysco/bessctl/bessctl run removal-servers\r\"
                        expect \"\\\\$\"
                        send \"exit\r\"
                "
            fi
	fi
    fi
}

init_clients() {
    if [ $SERVERS_AND_CLIENTS == 0 ]; then
	if [ $SINGLE_CORE == 1 ]; then
            if [ $HOSTNAME != $HOST_CLIENTS ]; then
                remote_exec $HOST_CLIENTS "
                        $REXEC su\n\"
                        expect \"Password: \"
                        send \"$PW\r\"
                        expect \"\\\\#\"
                        $REXEC /u/ronaldof/udysco/bessctl/bessctl daemon start\r\" 
                        $REXEC DYSCO=$1 /u/ronaldof/udysco/bessctl/bessctl run removal-clients-1core\r\"
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
                        send \"DYSCO=$1 /u/ronaldof/udysco/bessctl/bessctl run removal-clients-1core\r\"
                        expect \"\\\\$\"
                        send \"exit\r\"
                "
            fi
	else
	    if [ $HOSTNAME != $HOST_CLIENTS ]; then
                remote_exec $HOST_CLIENTS "
                        $REXEC su\n\"
                        expect \"Password: \"
                        send \"$PW\r\"
                        expect \"\\\\#\"
                        $REXEC /u/ronaldof/udysco/bessctl/bessctl daemon start\r\" 
                        $REXEC DYSCO=$1 /u/ronaldof/udysco/bessctl/bessctl run removal-clients\r\"
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
                        send \"DYSCO=$1 /u/ronaldof/udysco/bessctl/bessctl run removal-clients\r\"
                        expect \"\\\\$\"
                        send \"exit\r\"
                "
            fi  
	fi
    fi
}

get_cabernet_password

clear
echo $(TZ=America/Campo_Grande date)
echo -n "[$(TZ=America/Campo_Grande date +"%T.%6N")] Starting virtual machines... "
{
        init_proxy   $DYSCO
        init_servers $DYSCO
	init_clients $DYSCO
} &> /dev/null
sleep 35
echo "Done."
#echo -n "[$(TZ=America/Campo_Grande date +"%T.%6N")] Initializing proxy... "
#{
#    $EVALDIR/run-proxy.sh
#} &> /dev/null
#sleep 10
#echo "Done."
#echo -n "[$(TZ=America/Campo_Grande date +"%T.%6N")] Initializing iperf servers... "
#{
#    $EVALDIR/run-servers.sh
#} &> /dev/null
#sleep 25
#echo "Done."
echo -n "[$(TZ=America/Campo_Grande date +"%T.%6N")] Running the experiment... "
{
        $EVALDIR/run-clients.sh
} &> /dev/null
echo "Done."
sleep 5
echo -ne "\t[$(TZ=America/Campo_Grande date +"%T.%6N")] 1st reconfiguration... "
sleep $(($TIME_R1))
echo "Done."
echo -ne "\t[$(TZ=America/Campo_Grande date +"%T.%6N")] 2nd reconfiguration... "
sleep $(($TIME_R2-$TIME_R1))
echo "Done."
echo -ne "\t[$(TZ=America/Campo_Grande date +"%T.%6N")] 3rd reconfiguration... "
sleep $(($TIME_R3-$TIME_R2))
echo "Done."
echo -ne "\t[$(TZ=America/Campo_Grande date +"%T.%6N")] 4th reconfiguration... "
sleep $(($TIME_R4-$TIME_R3))
echo "Done."
echo -ne "\t[$(TZ=America/Campo_Grande date +"%T.%6N")] Finishing... "
sleep $(($DURATION-$TIME_R4))
echo "Done."
sleep 10
echo -n "[$(TZ=America/Campo_Grande date +"%T.%6N")] Collecting the results... "
{
        $EVALDIR/get_result.sh proxy
        $EVALDIR/get_result.sh servers
        $EVALDIR/get_result.sh clients
} &> /dev/null
echo "Done."

echo $(TZ=America/Campo_Grande date)
