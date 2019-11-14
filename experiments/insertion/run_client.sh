#!/bin/bash

TARGET_ADDRESS=$1
PORT=$2
DURATION=$3
CONN=$4
N=$5
LHOP=$6
RHOP=$7
NEW_MB=$8
TIME_REC=$9

DIR=/root/insertion

ESTABLISHED_TIME=2

/root/iperf -c $TARGET_ADDRESS -p $PORT -t $DURATION -P $CONN -f m -i 1 > $DIR/iperf_c$N.txt &

if [ $N != 1 ]; then
	sleep $TIME_REC
	netstat -napt | grep $PORT | grep ESTABLISHED > .tmp
	while read LINE; do
		LOCAL_IP=`echo $LINE | awk '{print $4}' | cut -d: -f1`
		NEIGH_IP=`echo $LINE | awk '{print $5}' | cut -d: -f1`
		LOCAL_PORT=`echo $LINE | awk '{print $4}' | cut -d: -f2`
		NEIGH_PORT=`echo $LINE | awk '{print $5}' | cut -d: -f2`
		$DIR/locking $LOCAL_IP $LOCAL_PORT $NEIGH_IP $NEIGH_PORT $LOCAL_IP $LOCAL_PORT $NEIGH_IP $NEIGH_PORT $LHOP $RHOP $NEW_MB $TARGET_ADDRESS
	done < .tmp
	rm .tmp
fi
