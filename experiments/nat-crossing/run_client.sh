#!/bin/bash

DIR=/root/nat/results

TARGET_ADDRESS=$1
PORT=$2
DURATION=$3
CONN=$4
DIRECTION=$5
LHOP=$6
RHOP=$7
TIME_REC=$8

SC=""
FIXED_ARGC=9 #8 + 1

for i in `seq $FIXED_ARGC $#`; do
	SC="$SC ${!i}"
done
SC="$SC $TARGET_ADDRESS"

/root/iperf -c $TARGET_ADDRESS -p $PORT -t $DURATION -P $CONN -i 1 -f m > $DIR/iperf_c1.txt &

sleep $TIME_REC
netstat -napt | grep $PORT | grep ESTABLISHED > .tmp
while read LINE; do
	LOCAL_IP=`echo $LINE | awk '{print $4}' | cut -d: -f1`
	NEIGH_IP=`echo $LINE | awk '{print $5}' | cut -d: -f1`
	LOCAL_PORT=`echo $LINE | awk '{print $4}' | cut -d: -f2`
	NEIGH_PORT=`echo $LINE | awk '{print $5}' | cut -d: -f2`
	$DIR/locking $LOCAL_IP $LOCAL_PORT $NEIGH_IP $NEIGH_PORT $LOCAL_IP $LOCAL_PORT $NEIGH_IP $NEIGH_PORT $DIRECTION $LHOP $RHOP $SC
done < .tmp
rm .tmp

#pkill -9 iperf
