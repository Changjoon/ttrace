#!/bin/bash

SCRIPT=`basename ${BASH_SOURCE[0]}`

#Help function
function HELP {
  echo -e \\n"Help documentation for ${SCRIPT}."\\n
  echo -e "Basic usage: $SCRIPT file.ext"\\n
  echo -e "-h  --Displays this help message. No further functions are performed."\\n
  exit 1
}

CONF="/etc/ttrace.conf"

SPACE=" "
COMMAND="atrace --async_start"
DEFTAGS=""

NUMARGS=$#
if [ $NUMARGS -eq 0 ]; then
  COMMAND=$COMMAND$SPACE$DEFTAGS
else
	shift $((OPTIND-1))  #This tells getopts to move on to the next argument.
	while [ $# -ne 0 ]; do
		PARAM=$1
		COMMAND=$COMMAND$SPACE$PARAM
		shift
	done
fi

echo "COMMAND is: $COMMAND"
echo "$COMMAND" > "$CONF"

sync
sleep 1
reboot -f

exit 0
