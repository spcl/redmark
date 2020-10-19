#!/bin/bash

define(){ IFS='\n' read -r -d '' ${1} || true; }
declare -A pids
redirection=( "> out" "2> err" "< /dev/null" )
define HELP <<'EOF'

Script for laucnhing the attack example.
usage  : $0 [options]
EOF
 
attackers=0
ipbase="192.168.1."
ipstart="71"

attacker_type=""
client_type=""
size=4096
outstand=16
num=1024
outstandattack=120
attackmessagesize=1024

for arg in "$@"
do
    case ${arg} in
    --help|-help|-h)
        usage
        exit 1
        ;;
    --outstandattack=*)
        outstandattack=`echo $arg | sed -e 's/--outstandattack=//'`
        outstandattack=`eval echo ${outstandattack}`    # tilde and variable expansion
        ;;
    --attackers=*)
        attackers=`echo $arg | sed -e 's/--attackers=//'`
        attackers=`eval echo ${attackers}`    # tilde and variable expansion
        ;;
    --writeattack)
        attacker_type="--write"
        ;;
    --writeclient)
        client_type="--write"
        ;;
    --size=*)
        size=`echo $arg | sed -e 's/--size=//'`
        size=`eval echo ${size}`    # tilde and variable expansion
        ;;
    --outstand=*)
        outstand=`echo $arg | sed -e 's/--outstand=//'`
        outstand=`eval echo ${outstand}`    # tilde and variable expansion
        ;;
    --num=*)
        num=`echo $arg | sed -e 's/--num=//'`
        num=`eval echo ${num}`    # tilde and variable expansion
        ;;
    esac
done

StartServer() {
    echo "Starting a victim server..."
    
    cmd=( "ssh" "-oStrictHostKeyChecking=no" "$USER@${ipbase}${ipstart}" "nohup" "${PWD}/victim --address=${ipbase}${ipstart} --reads=16 --len=4096 --connections=$(($attackers + 1))" "${redirection[@]}" "&" "echo \$!" )
    pids["${ipbase}${ipstart}"]=$("${cmd[@]}")
    echo -e "COMMAND: "${cmd[@]}
    
    echo -e "\tinitial nodes: ${!pids[@]}"
    echo -e "\t...and their PIDs: ${pids[@]}"
}


StartAttackers() {
    echo "Starting $attackers attackers..."
    for ((i=0; i<$attackers; i++)); do
        ipend=$(($ipstart+$i + 1))
        cmd=( "ssh" "-oStrictHostKeyChecking=no" "$USER@${ipbase}${ipend}" "nohup" "${PWD}/attacker  --address=${ipbase}${ipstart} --size=${attackmessagesize} --outstand=${outstandattack} ${attacker_type}" "${redirection[@]}" "&" "echo \$!" )
        pids["${ipbase}${ipend}"]=$("${cmd[@]}")
        echo -e "COMMAND: "${cmd[@]}
	sleep 1
    done
    echo -e "\tinitial nodes: ${!pids[@]}"
    echo -e "\t...and their PIDs: ${pids[@]}"
}

StopServers() {
    for i in "${!pids[@]}"
    do
        cmd=( "ssh" "$USER@$i" "kill -9" "${pids[$i]}" )
        echo "Executing: ${cmd[@]}"
        $("${cmd[@]}")
    done
}


trap 'echo -ne "Stop all servers..." && StopServers && echo "done" && exit 1' INT

StartServer
echo "Server is started!"
sleep 1

interval=100

# scale interval for large message sizes. 
# interval stands for the number of completions required for a single measurement
coef=$(($size/1024))
if [ "$coef" -ne "0" ]; then
interval=$((128/$coef))
fi
StartAttackers
./client --address=${ipbase}${ipstart} --size=${size}  --outstand=${outstand} --num=${num} --interval=${interval} ${client_type}

StopServers
