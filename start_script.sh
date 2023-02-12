#!/bin/bash

if pgrep -f fortigate_get_sessions_tabel.py > /dev/null
then
    echo "Script is running"
else
    /usr/bin/python3 /home/<user>/fortigate_sessions_list/fortigate_get_sessions_tabel.py &
fi
