control_port=3100
low_port=3101
high_port=3104

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
process=""
if [ -z "$key" ] ; then
  echo "No key given" >> /dev/stderr
  exit 1;
fi
for port in $(seq -w $low_port $high_port)
do
  respawn node index.js --agent --only_known --tcp --bind :$port  --connect_key $key  & # --ca_path CACertificates.p7b 
  process="$process $!"
done

respawn node index.js --proxy  --bind :$control_port --ports $low_port:$high_port --connect_key bdc7b38e820bd95d5a42bd3566638479332b6704332573af05ff931a1cdbda07  &
process="$process $!"



trap stop USR1
trap stop USR2
trap stop INT

for pid in $process
do
  wait $pid
done
