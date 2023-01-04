project_path=$(pwd)
echo -e "loading project functions"

function run_all(){
  local NUM_CLIENTS=4
  local MAX_CLIENTS=4
  while [ "$1" != "" ]; do
    local PARAM=`echo $1 | awk -F= '{print $1}'`
    local VALUE=`echo $1 | awk -F= '{print $2}'`

    case $PARAM in
        -h | --help)
            help
            ;;
        -num_clients)
          NUM_CLIENTS=$VALUE
          echo -e "num_clients = $NUM_CLIENTS"
          ;;
        -max_clients)
          MAX_CLIENTS=$VALUE
          echo -e "MAX_CLIENTS = $MAX_CLIENTS"
          ;;
        *)
            echo "ERROR: unknown parameter \"$PARAM\"\n"
            help
            ;;
    esac
    shift
  done

	gnome-terminal -q --geometry 90x25+1100+570 -- bash -c "python3 $project_path/server.py $MAX_CLIENTS"
	local x=0
	local y=0
	for i in $(seq $NUM_CLIENTS)
	do
	sleep 0
	if [ $i -eq 1 ] ; then
    x=0
    y=0
	fi
	if [ $i -eq 2 ] ; then
    x=0
    y=570
	fi
	if [ $i -eq 3 ] ; then
    x=1100
    y=0
	fi
	if [ $i -eq 4 ] ; then
    x=1100
    y=570
	fi
	gnome-terminal -q --geometry 90x25+$x+$y -- bash -c "python3 $project_path/client.py"
	done
}

function s(){
	python3 $project_path/server.py
}

function c(){
	python3 $project_path/client.py
}

function show() {
  ps -fA | grep python
}

function help(){
	echo -e "Usage: \n"
	echo -e "s  . . . . . . . . . . . . . . . . . . . . run only the server"
	echo -e "c  . . . . . . . . . . . . . . . . . . . . run only the client"
	echo -e "show . . . . . . . . . . . . . . . . . . . Show python process"
	echo -e "run_all -num_clients=[4] -max_clients=[4]  run one server instance and [value] clients "
}
help