#!/bin/bash
. /home/oracle/.bash_profile >/dev/null 2>&1
pgrep -f "^/[^ ]*/dgmgrl .*START OBSERVER" >/dev/null && exit 0
dgmgrl -silent /@orcl3 "start observer obs-r2 in background file is '/home/oracle/observer/fsfo_orcl3.dat' logfile is '/home/oracle/observer/observer_orcl3.log' connect identifier is orcl3" >> /home/oracle/observer/start_observer.out 2>&1 </dev/null
