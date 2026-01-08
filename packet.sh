#!/bin/bash

# path to pipe lies in .env
source .env

# python script name
PYTHON_SCRIPT="packet.py"

# read usernum for python script
read -p "Usernum: " USERNUM

# create pipe if npt exist, ensures it will exist by the time python script starts
if [ ! -p "$PIPE" ]; then
    mkfifo "$PIPE"
fi

# function for safe cleanup
function cleanup() {
    # check if process still runs, kill it if yes, also ignore errors
    [ -n "$PY_PID" ] && kill $PY_PID 2>/dev/null
    # restore terminal to default
    stty echo icanon isig
    # remove pipe
    rm -f $PIPE
    # successful exit
    exit 0
}

# catch exit/CTRL+C/kill signal and call cleanup function
trap cleanup EXIT INT TERM

# START with terminal settings
# turn off echo, get symbols directly without Enter, allow special symbols as CTRL+C
stty -echo -icanon isig

# run python script in the background and catch its process id
python3 "$PYTHON_SCRIPT" "$USERNUM" &
PY_PID=$!

# start values
RX=0; RX_MAX=0; TX=0; TX_MAX=0

echo "Packet statistics"

while true; do
    # check if python script process finished, then exit with error
    if ! kill -0 $PY_PID 2>/dev/null; then
        echo "Error: Python collector died."
        exit 1
    fi

    # with little timeout, get all lines from pipe to find last one
    while read -t 0.01 line < $PIPE; do
        # read line into temporary variables
        read RX_VAL RX_MAX_VAL TX_VAL TX_MAX_VAL <<< "$line"
        # if some temporary variables are null, they won't be overwritten
        RX=$RX_VAL; RX_MAX=$RX_MAX_VAL; TX=$TX_VAL; TX_MAX=$TX_MAX_VAL
    done

    # ansi code \033[3A moves cursor 3 lines up
    printf "\033[3A"
    
    # print rx and tx megabit with reserved space and their maximums, \r means carriage return to overwrite string
    printf "\rRX: %4s Mbit (Max: %4s)\n" "$RX" "$RX_MAX"
    printf "\rTX: %4s Mbit (Max: %4s)\n" "$TX" "$TX_MAX"
    
    # print status bar with quit and refresh, \e[7m and \e[27m indicate inverse mode output, \r to overwrite string
    printf "\r\e[7mq\e[27m Quit  \e[7mr\e[27m Refresh\n"

    # loop waiting for quit or refresh symbol
    while true; do
        # wait for 1 second to read 1 symbol into variable
        read -n 1 -t 0.5 input
        
        # get previous command's status (read)
        status=$?

        # if status >128, it's timeout, break and refresh page
        if [ $status -gt 128 ]; then
            break
        fi

        # if not, input is not empty
        case "$input" in
            # successful quit if q pressed
            q|Q)
                exit 0
                ;;
            # break and refresh page quickly if r pressed
            r|R)
                break
                ;;
        esac
    done
done