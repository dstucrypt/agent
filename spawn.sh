#!/bin/bash

control_port=3100

respawn() {
  while true
  do
    echo start
    $@ || true
    echo done!
  done
}
stop() {
  kill $process
}


key=$1
num=$2
if [ -z "$num" ] ;then
num=4
fi

process=""
if [ -z "$key" ] ; then
  echo "No key given" >> /dev/stderr
  exit 1;
fi

limit=$(cat /proc/cpuinfo  | grep -E '^processor' | wc -l)
for x in $(seq 1 $num)
do
  cpu=$[ ($x - 1) % $limit ]
  port=$[ $control_port + $x ]
  respawn taskset --cpu-list $cpu node index.js --agent  --tcp --bind :$port  --connect_key $key  --only_known --ca_path CACertificates.p7b &
  process="$process $!"
done

respawn node index.js --proxy  --bind :$control_port --ports $[ $control_port + 1 ]:$[ $control_port + $num ] --connect_key $key  &
process="$process $!"



trap stop USR1
trap stop USR2
trap stop INT

for pid in $process
do
  wait $pid
done
